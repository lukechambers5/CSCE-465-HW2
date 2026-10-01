import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import handshake
import secure_record as sr
from handshake import Hello, HandshakeError

CMD = b'{"action":"READ","path":"notes.txt"}'


@pytest.fixture(scope="module")
def params():
    return handshake.load_group()


@pytest.fixture(scope="module")
def rsa_keys():
    return [rsa.generate_private_key(65537, handshake.RSA_BITS) for _ in range(3)]


@pytest.fixture
def parties(params, rsa_keys):
    return handshake.make_parties(params, rsa_keys[0], rsa_keys[1])


@pytest.fixture
def channels(parties):
    gateway, node = parties
    gk, nk = handshake.run_handshake(gateway, node)
    g_tx, g_rx = sr.make_channels(gk, True)
    n_tx, n_rx = sr.make_channels(nk, False)
    return g_tx, g_rx, n_tx, n_rx


def flip(data, index):
    b = bytearray(data)
    b[index] ^= 0x01
    return bytes(b)


def test_valid_handshake_and_bidirectional_messages(parties):
    gateway, node = parties
    gk, nk = handshake.run_handshake(gateway, node)
    assert gk == nk
    assert len(gk.session_id) == 8
    assert len({gk.g2n_enc, gk.g2n_mac, gk.n2g_enc, gk.n2g_mac}) == 4
    g_tx, g_rx = sr.make_channels(gk, True)
    n_tx, n_rx = sr.make_channels(nk, False)
    for i in range(3):
        msg = CMD + bytes([i])
        assert sr.open_record(n_rx, sr.seal(g_tx, 1, msg)) == (1, msg)
        reply = b"ok-%d" % i
        assert sr.open_record(g_rx, sr.seal(n_tx, 2, reply)) == (2, reply)


def test_sequence_numbers_start_at_zero_and_increment(channels):
    g_tx, _, n_tx, _ = channels
    r0 = sr.seal(g_tx, 1, b"a")
    r1 = sr.seal(g_tx, 1, b"b")
    n0 = sr.seal(n_tx, 1, b"c")
    assert int.from_bytes(r0[2:10], "big") == 0
    assert int.from_bytes(r1[2:10], "big") == 1
    assert int.from_bytes(n0[2:10], "big") == 0


def test_modified_ciphertext_rejected_and_state_unchanged(channels):
    g_tx, _, _, n_rx = channels
    record = sr.seal(g_tx, 1, CMD)
    with pytest.raises(sr.AuthenticationFailure):
        sr.open_record(n_rx, flip(record, sr.HEADER_LEN))
    assert n_rx.seq == 0
    assert sr.open_record(n_rx, record) == (1, CMD)


def test_modified_tag_rejected(channels):
    g_tx, _, _, n_rx = channels
    record = sr.seal(g_tx, 1, CMD)
    with pytest.raises(sr.AuthenticationFailure):
        sr.open_record(n_rx, flip(record, len(record) - 1))


@pytest.mark.parametrize(
    "index,expected",
    [
        (0, sr.MalformedRecord),
        (1, sr.WrongDirection),
        (2, sr.AuthenticationFailure),
        (9, sr.AuthenticationFailure),
        (10, sr.AuthenticationFailure),
        (14, sr.MalformedRecord),
    ],
)
def test_modified_authenticated_header_rejected(channels, index, expected):
    g_tx, _, _, n_rx = channels
    record = sr.seal(g_tx, 1, CMD)
    with pytest.raises(expected):
        sr.open_record(n_rx, flip(record, index))
    assert n_rx.seq == 0
    assert sr.open_record(n_rx, record) == (1, CMD)


def test_truncated_record_rejected(channels):
    g_tx, _, _, n_rx = channels
    record = sr.seal(g_tx, 1, CMD)
    with pytest.raises(sr.MalformedRecord):
        sr.open_record(n_rx, record[:-1])
    with pytest.raises(sr.MalformedRecord):
        sr.open_record(n_rx, record[:10])


def test_replayed_record_rejected(channels):
    g_tx, _, _, n_rx = channels
    record = sr.seal(g_tx, 1, CMD)
    assert sr.open_record(n_rx, record) == (1, CMD)
    with pytest.raises(sr.ReplayError):
        sr.open_record(n_rx, record)


def test_out_of_order_record_rejected(channels):
    g_tx, _, _, n_rx = channels
    first = sr.seal(g_tx, 1, b"first")
    second = sr.seal(g_tx, 1, b"second")
    with pytest.raises(sr.ReplayError):
        sr.open_record(n_rx, second)
    assert sr.open_record(n_rx, first) == (1, b"first")
    assert sr.open_record(n_rx, second) == (1, b"second")


def test_record_reflected_to_sender_rejected(channels):
    g_tx, g_rx, n_tx, n_rx = channels
    from_node = sr.seal(n_tx, 2, b"status")
    with pytest.raises(sr.WrongDirection):
        sr.open_record(n_rx, from_node)
    from_gateway = sr.seal(g_tx, 1, CMD)
    with pytest.raises(sr.WrongDirection):
        sr.open_record(g_rx, from_gateway)


def test_reflected_record_with_rewritten_direction_fails_mac(channels):
    _, _, n_tx, n_rx = channels
    from_node = sr.seal(n_tx, 2, b"status")
    with pytest.raises(sr.AuthenticationFailure):
        sr.open_record(n_rx, flip(from_node, 1))


def test_wrong_session_keys_rejected(params, rsa_keys, channels):
    g_tx, _, _, _ = channels
    other_g, other_n = handshake.make_parties(params, rsa_keys[0], rsa_keys[1])
    handshake.run_handshake(other_g, other_n)
    _, other_rx = sr.make_channels(other_n.keys, False)
    with pytest.raises(sr.AuthenticationFailure):
        sr.open_record(other_rx, sr.seal(g_tx, 1, CMD))


def test_sender_never_reuses_iv(channels):
    g_tx, _, _, _ = channels
    seqs = [sr.seal(g_tx, 1, b"x")[2:10] for _ in range(20)]
    assert len(set(seqs)) == 20


def test_sequence_exhaustion_refuses_to_seal(channels):
    g_tx, _, _, _ = channels
    g_tx.seq = sr.MAX_SEQ
    sr.seal(g_tx, 1, b"last")
    with pytest.raises(sr.SequenceExhausted):
        sr.seal(g_tx, 1, b"too many")


def test_wrong_rsa_public_key_rejected(parties, rsa_keys):
    gateway, node = parties
    gateway.peer_public_key = rsa_keys[2].public_key()
    node_hello, node_sig = node.respond(gateway.start())
    with pytest.raises(HandshakeError, match="invalid peer signature"):
        gateway.accept(node_hello, node_sig)
    assert gateway.keys is None


def test_invalid_signature_rejected(parties):
    gateway, node = parties
    node_hello, node_sig = node.respond(gateway.start())
    with pytest.raises(HandshakeError, match="invalid peer signature"):
        gateway.accept(node_hello, flip(node_sig, 0))
    assert gateway.keys is None


def test_signature_by_untrusted_key_rejected(params, rsa_keys):
    gateway, _ = handshake.make_parties(params, rsa_keys[0], rsa_keys[1])
    _, impostor = handshake.make_parties(params, rsa_keys[0], rsa_keys[2])
    node_hello, node_sig = impostor.respond(gateway.start())
    with pytest.raises(HandshakeError, match="invalid peer signature"):
        gateway.accept(node_hello, node_sig)


def test_reflected_handshake_message_rejected(parties):
    gateway, _ = parties
    own_hello = gateway.start()
    with pytest.raises(HandshakeError, match="unexpected peer identity"):
        gateway.accept(own_hello, b"\x00" * 384)
    disguised = Hello(handshake.NODE_ID, own_hello.pub, own_hello.nonce)
    with pytest.raises(HandshakeError, match="reflected handshake message"):
        gateway.accept(disguised, b"\x00" * 384)


def test_modified_nonce_rejected(parties):
    gateway, node = parties
    h = gateway.start()
    altered = Hello(h.identity, h.pub, flip(h.nonce, 0))
    node_hello, node_sig = node.respond(altered)
    with pytest.raises(HandshakeError, match="invalid peer signature"):
        gateway.accept(node_hello, node_sig)


def test_modified_dh_public_value_rejected(parties):
    gateway, node = parties
    node_hello, node_sig = node.respond(gateway.start())
    altered = Hello(node_hello.identity, flip(node_hello.pub, 383), node_hello.nonce)
    with pytest.raises(HandshakeError, match="invalid peer signature"):
        gateway.accept(altered, node_sig)


def test_unexpected_peer_identity_rejected(parties):
    gateway, node = parties
    node.identity = b"evil-node"
    node_hello, node_sig = node.respond(gateway.start())
    with pytest.raises(HandshakeError, match="unexpected peer identity"):
        gateway.accept(node_hello, node_sig)


def test_malformed_transcript_rejected_before_hashing(parties):
    gateway, node = parties
    node_hello, _ = node.respond(gateway.start())
    blob = handshake.build_transcript(gateway.hello, node_hello)
    with pytest.raises(HandshakeError, match="declared length exceeds data"):
        handshake.transcript_hash(flip(blob, 3))
    with pytest.raises(HandshakeError, match="wrong field count"):
        handshake.transcript_hash(blob + b"\x00\x00\x00\x00")
    with pytest.raises(HandshakeError):
        handshake.transcript_hash(blob[:-1])


def test_dh_values_and_nonces_are_fresh_per_session(params, rsa_keys):
    seen = set()
    for _ in range(3):
        g, n = handshake.make_parties(params, rsa_keys[0], rsa_keys[1])
        handshake.run_handshake(g, n)
        seen.add((g.hello.pub, g.hello.nonce, n.hello.pub, n.hello.nonce, g.keys.session_id))
    assert len(seen) == 3


def test_handshake_discards_dh_private_values(parties):
    gateway, node = parties
    handshake.run_handshake(gateway, node)
    assert gateway.dh_private is None and node.dh_private is None
