import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

VERSION = 1
DIR_G2N = 0
DIR_N2G = 1
HEADER_FORMAT = ">BBQBI"
HEADER_LEN = struct.calcsize(HEADER_FORMAT)
TAG_LEN = 32
MAX_SEQ = 2**64 - 1
MAX_CT_LEN = 2**32 - 1


class RecordError(Exception):
    pass


class MalformedRecord(RecordError):
    pass


class WrongDirection(RecordError):
    pass


class AuthenticationFailure(RecordError):
    pass


class ReplayError(RecordError):
    pass


class SequenceExhausted(RecordError):
    pass


class ChannelState:
    def __init__(self, direction, k_enc, k_mac, session_id):
        if direction not in (DIR_G2N, DIR_N2G):
            raise ValueError("bad direction")
        if len(k_enc) != 32 or len(k_mac) != 32 or len(session_id) != 8:
            raise ValueError("bad key or session id length")
        self.direction = direction
        self.k_enc = k_enc
        self.k_mac = k_mac
        self.session_id = session_id
        self.seq = 0


def make_channels(keys, is_gateway):
    g2n = (DIR_G2N, keys.g2n_enc, keys.g2n_mac, keys.session_id)
    n2g = (DIR_N2G, keys.n2g_enc, keys.n2g_mac, keys.session_id)
    if is_gateway:
        return ChannelState(*g2n), ChannelState(*n2g)
    return ChannelState(*n2g), ChannelState(*g2n)


def make_iv(session_id, seq):
    return session_id + struct.pack(">Q", seq)


def aes_ctr(key, iv, data):
    c = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return c.update(data) + c.finalize()


def new_mac(k_mac, header, iv, ciphertext):
    h = hmac.HMAC(k_mac, hashes.SHA256())
    h.update(header + iv + ciphertext)
    return h


def seal(state, message_type, plaintext):
    if not 0 <= message_type <= 255:
        raise ValueError("message_type must fit in one byte")
    if len(plaintext) > MAX_CT_LEN:
        raise ValueError("plaintext too long")
    if state.seq > MAX_SEQ:
        raise SequenceExhausted("sequence space exhausted; rekey required")
    seq = state.seq
    iv = make_iv(state.session_id, seq)
    ciphertext = aes_ctr(state.k_enc, iv, plaintext)
    header = struct.pack(HEADER_FORMAT, VERSION, state.direction, seq, message_type, len(ciphertext))
    tag = new_mac(state.k_mac, header, iv, ciphertext).finalize()
    state.seq = seq + 1
    return header + ciphertext + tag


def open_record(state, record):
    if len(record) < HEADER_LEN + TAG_LEN:
        raise MalformedRecord("record too short")
    header = record[:HEADER_LEN]
    version, direction, seq, message_type, ct_len = struct.unpack(HEADER_FORMAT, header)
    if len(record) != HEADER_LEN + ct_len + TAG_LEN:
        raise MalformedRecord("declared ciphertext length does not match record")
    if version != VERSION:
        raise MalformedRecord("unsupported version")
    if direction != state.direction:
        raise WrongDirection("record is for the other direction")
    ciphertext = record[HEADER_LEN:HEADER_LEN + ct_len]
    tag = record[HEADER_LEN + ct_len:]
    iv = make_iv(state.session_id, seq)
    try:
        new_mac(state.k_mac, header, iv, ciphertext).verify(tag)
    except InvalidSignature:
        raise AuthenticationFailure("MAC verification failed") from None
    if seq != state.seq:
        raise ReplayError("unexpected sequence number (replay or reordering)")
    plaintext = aes_ctr(state.k_enc, iv, ciphertext)
    state.seq = seq + 1
    return message_type, plaintext


def main():
    import handshake

    gateway, node = handshake.make_parties()
    gk, nk = handshake.run_handshake(gateway, node)
    g_tx, g_rx = make_channels(gk, True)
    n_tx, n_rx = make_channels(nk, False)

    def attempt(name, fn):
        try:
            fn()
            print(f"{name}: ACCEPTED (bad)")
        except RecordError as e:
            print(f"{name}: rejected -> {type(e).__name__}: {e}")

    def flip(record, index):
        b = bytearray(record)
        b[index] ^= 1
        return bytes(b)

    cmd = b'{"action":"READ","path":"notes.txt"}'
    r0 = seal(g_tx, 1, cmd)
    print("gateway -> node:", r0.hex())
    print("node opened:", open_record(n_rx, r0))
    reply = seal(n_tx, 2, b'{"status":"ok"}')
    print("node -> gateway opened:", open_record(g_rx, reply))

    r1 = seal(g_tx, 1, cmd)
    attempt("modified ciphertext", lambda: open_record(n_rx, flip(r1, HEADER_LEN)))
    attempt("modified message_type", lambda: open_record(n_rx, flip(r1, 10)))
    attempt("modified sequence", lambda: open_record(n_rx, flip(r1, 9)))
    attempt("modified length", lambda: open_record(n_rx, flip(r1, 14)))
    attempt("modified tag", lambda: open_record(n_rx, flip(r1, len(r1) - 1)))
    print("untouched record still accepted:", open_record(n_rx, r1))
    attempt("replayed record", lambda: open_record(n_rx, r1))

    r2 = seal(n_tx, 2, b"hello gateway")
    attempt("own record reflected to sender", lambda: open_record(n_rx, r2))
    attempt("reflected, direction byte rewritten", lambda: open_record(n_rx, flip(r2, 1)))
    print("gateway accepts it normally:", open_record(g_rx, r2))

    ra = seal(g_tx, 1, b"first")
    rb = seal(g_tx, 1, b"second")
    attempt("out-of-order record", lambda: open_record(n_rx, rb))
    print("in order:", open_record(n_rx, ra), open_record(n_rx, rb))


if __name__ == "__main__":
    main()
