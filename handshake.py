import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa

LABEL = b"CSCE465-HS-v2"
GROUP_ID = b"ffdhe3072"
KDF_LABEL = b"CSCE465-KDF-v1"
DH_BYTES = 384
NONCE_BYTES = 16
RSA_BITS = 3072
GATEWAY_ID = b"gateway-01"
NODE_ID = b"node-01"
ROLE_GATEWAY = b"gateway"
ROLE_NODE = b"node"
PARAMS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ffdhe3072.pem")
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)


class HandshakeError(Exception):
    pass


@dataclass(frozen=True)
class Hello:
    identity: bytes
    pub: bytes
    nonce: bytes


@dataclass(frozen=True)
class SessionKeys:
    g2n_enc: bytes
    g2n_mac: bytes
    n2g_enc: bytes
    n2g_mac: bytes
    session_id: bytes


def sha256(data):
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


def hmac_sha256(key, data):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def int_to_bytes(n):
    return n.to_bytes(DH_BYTES, "big")


def load_group(path=PARAMS_PATH):
    with open(path, "rb") as f:
        params = serialization.load_pem_parameters(f.read())
    nums = params.parameter_numbers()
    if nums.p.bit_length() != 3072 or nums.g != 2:
        raise HandshakeError("group file is not ffdhe3072")
    return params


def encode_transcript(fields):
    return b"".join(struct.pack(">I", len(f)) + f for f in fields)


def parse_transcript(blob):
    fields = []
    pos = 0
    while pos < len(blob):
        if len(blob) - pos < 4:
            raise HandshakeError("malformed transcript: truncated length")
        (n,) = struct.unpack_from(">I", blob, pos)
        pos += 4
        if n > len(blob) - pos:
            raise HandshakeError("malformed transcript: declared length exceeds data")
        fields.append(blob[pos:pos + n])
        pos += n
    if len(fields) != 8:
        raise HandshakeError("malformed transcript: wrong field count")
    label, group, gw_id, node_id, gw_pub, node_pub, gw_nonce, node_nonce = fields
    if label != LABEL or group != GROUP_ID:
        raise HandshakeError("malformed transcript: wrong label or group")
    if not gw_id or not node_id:
        raise HandshakeError("malformed transcript: empty identity")
    if len(gw_pub) != DH_BYTES or len(node_pub) != DH_BYTES:
        raise HandshakeError("malformed transcript: bad public value length")
    if len(gw_nonce) != NONCE_BYTES or len(node_nonce) != NONCE_BYTES:
        raise HandshakeError("malformed transcript: bad nonce length")
    return fields


def transcript_hash(blob):
    parse_transcript(blob)
    return sha256(blob)


def build_transcript(gw_hello, node_hello):
    return encode_transcript([
        LABEL,
        GROUP_ID,
        gw_hello.identity,
        node_hello.identity,
        gw_hello.pub,
        node_hello.pub,
        gw_hello.nonce,
        node_hello.nonce,
    ])


def derive_keys(z, th):
    k_master = sha256(KDF_LABEL + z + th)

    def k(label):
        return hmac_sha256(k_master, label + th)

    return SessionKeys(
        g2n_enc=k(b"gateway-to-node encryption"),
        g2n_mac=k(b"gateway-to-node MAC"),
        n2g_enc=k(b"node-to-gateway encryption"),
        n2g_mac=k(b"node-to-gateway MAC"),
        session_id=k(b"session identifier")[:8],
    )


class Party:
    def __init__(self, role, identity, signing_key, peer_identity, peer_public_key, params):
        self.role = role
        self.peer_role = ROLE_NODE if role == ROLE_GATEWAY else ROLE_GATEWAY
        self.identity = identity
        self.signing_key = signing_key
        self.peer_identity = peer_identity
        self.peer_public_key = peer_public_key
        self.params = params
        self.dh_private = None
        self.hello = None
        self.peer_hello = None
        self.keys = None

    def new_hello(self):
        self.dh_private = self.params.generate_private_key()
        y = self.dh_private.public_key().public_numbers().y
        self.hello = Hello(self.identity, int_to_bytes(y), os.urandom(NONCE_BYTES))
        return self.hello

    def check_peer_hello(self, hello):
        if hello.identity != self.peer_identity:
            raise HandshakeError("unexpected peer identity")
        if hello.identity == self.identity:
            raise HandshakeError("reflected handshake message")
        if len(hello.pub) != DH_BYTES or len(hello.nonce) != NONCE_BYTES:
            raise HandshakeError("bad field length in hello")
        p = self.params.parameter_numbers().p
        y = int.from_bytes(hello.pub, "big")
        if not 2 <= y <= p - 2:
            raise HandshakeError("invalid peer public value")
        if self.hello is not None and (hello.pub == self.hello.pub or hello.nonce == self.hello.nonce):
            raise HandshakeError("reflected handshake message")
        self.peer_hello = hello

    def transcript(self):
        if self.role == ROLE_GATEWAY:
            return build_transcript(self.hello, self.peer_hello)
        return build_transcript(self.peer_hello, self.hello)

    def sign(self):
        th = transcript_hash(self.transcript())
        return self.signing_key.sign(self.role + th, PSS, hashes.SHA256())

    def verify_peer(self, signature):
        th = transcript_hash(self.transcript())
        try:
            self.peer_public_key.verify(signature, self.peer_role + th, PSS, hashes.SHA256())
        except InvalidSignature:
            raise HandshakeError("invalid peer signature") from None

    def derive(self):
        nums = self.params.parameter_numbers()
        peer_y = int.from_bytes(self.peer_hello.pub, "big")
        peer_key = dh.DHPublicNumbers(peer_y, nums).public_key()
        z = int_to_bytes(int.from_bytes(self.dh_private.exchange(peer_key), "big"))
        th = transcript_hash(self.transcript())
        self.keys = derive_keys(z, th)
        self.dh_private = None

    def start(self):
        return self.new_hello()

    def respond(self, peer_hello):
        self.new_hello()
        self.check_peer_hello(peer_hello)
        return self.hello, self.sign()

    def accept(self, peer_hello, peer_signature):
        self.check_peer_hello(peer_hello)
        self.verify_peer(peer_signature)
        signature = self.sign()
        self.derive()
        return signature

    def confirm(self, peer_signature):
        self.verify_peer(peer_signature)
        self.derive()


def make_parties(params=None, gateway_key=None, node_key=None):
    params = params or load_group()
    gateway_key = gateway_key or rsa.generate_private_key(65537, RSA_BITS)
    node_key = node_key or rsa.generate_private_key(65537, RSA_BITS)
    gateway = Party(ROLE_GATEWAY, GATEWAY_ID, gateway_key, NODE_ID, node_key.public_key(), params)
    node = Party(ROLE_NODE, NODE_ID, node_key, GATEWAY_ID, gateway_key.public_key(), params)
    return gateway, node


def run_handshake(gateway, node):
    gw_hello = gateway.start()
    node_hello, node_sig = node.respond(gw_hello)
    gw_sig = gateway.accept(node_hello, node_sig)
    node.confirm(gw_sig)
    return gateway.keys, node.keys


def main():
    params = load_group()
    gw_key = rsa.generate_private_key(65537, RSA_BITS)
    node_key = rsa.generate_private_key(65537, RSA_BITS)
    attacker_key = rsa.generate_private_key(65537, RSA_BITS)

    gateway, node = make_parties(params, gw_key, node_key)
    gk, nk = run_handshake(gateway, node)
    print("handshake ok, keys match:", gk == nk)
    print("session_id:", gk.session_id.hex())
    print("TH:", transcript_hash(gateway.transcript()).hex())

    def attempt(name, fn):
        try:
            fn()
            print(f"{name}: ACCEPTED (bad)")
        except HandshakeError as e:
            print(f"{name}: rejected -> {e}")

    def tampered_nonce():
        g, n = make_parties(params, gw_key, node_key)
        h = g.start()
        flipped = Hello(h.identity, h.pub, bytes([h.nonce[0] ^ 1]) + h.nonce[1:])
        node_hello, node_sig = n.respond(flipped)
        g.accept(node_hello, node_sig)

    def tampered_public_value():
        g, n = make_parties(params, gw_key, node_key)
        node_hello, node_sig = n.respond(g.start())
        y = int.from_bytes(node_hello.pub, "big") ^ 1
        g.accept(Hello(node_hello.identity, int_to_bytes(y), node_hello.nonce), node_sig)

    def wrong_identity():
        g, n = make_parties(params, gw_key, node_key)
        n.identity = b"evil-node"
        node_hello, node_sig = n.respond(g.start())
        g.accept(node_hello, node_sig)

    def reflected_hello():
        g, _ = make_parties(params, gw_key, node_key)
        h = g.start()
        g.accept(h, b"\x00" * 384)

    def reflected_hello_renamed():
        g, _ = make_parties(params, gw_key, node_key)
        h = g.start()
        g.accept(Hello(NODE_ID, h.pub, h.nonce), b"\x00" * 384)

    def attacker_signature():
        g, _ = make_parties(params, gw_key, node_key)
        _, n = make_parties(params, gw_key, attacker_key)
        node_hello, node_sig = n.respond(g.start())
        g.accept(node_hello, node_sig)

    def wrong_pubkey_configured():
        g, n = make_parties(params, gw_key, node_key)
        g.peer_public_key = attacker_key.public_key()
        node_hello, node_sig = n.respond(g.start())
        g.accept(node_hello, node_sig)

    def malformed_transcript():
        g, n = make_parties(params, gw_key, node_key)
        node_hello, _ = n.respond(g.start())
        blob = bytearray(build_transcript(g.hello, node_hello))
        blob[3] += 1
        transcript_hash(bytes(blob))

    attempt("modified nonce", tampered_nonce)
    attempt("modified DH public value", tampered_public_value)
    attempt("unexpected peer identity", wrong_identity)
    attempt("reflected hello", reflected_hello)
    attempt("reflected hello, identity rewritten", reflected_hello_renamed)
    attempt("signature by wrong RSA key", attacker_signature)
    attempt("wrong peer RSA public key", wrong_pubkey_configured)
    attempt("malformed transcript length", malformed_transcript)


if __name__ == "__main__":
    main()
