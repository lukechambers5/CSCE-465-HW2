import json
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PLAINTEXT = b'{"action":"READ","path":"notes.txt"}'
OLD, NEW = b"READ", b"WIPE"


def ctr(key, nonce, data):
    c = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return c.update(data) + c.finalize()


def xor(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


class Receiver:
    def __init__(self, key):
        self.key = key
        self.executed = []

    def process(self, nonce, ct):
        pt = ctr(self.key, nonce, ct)
        cmd = json.loads(pt)
        self.executed.append(cmd)
        print(f"  receiver executed: {cmd}")


def relay_tamper(nonce, ct, known_plain):
    off = known_plain.index(OLD)
    delta = xor(OLD, NEW)
    forged = bytearray(ct)
    for i, d in enumerate(delta):
        forged[off + i] ^= d
    return nonce, bytes(forged)


def main():
    key = os.urandom(32)
    nonce = os.urandom(16)
    rx = Receiver(key)

    ct = ctr(key, nonce, PLAINTEXT)
    print("[1] Original")
    print("  plaintext :", PLAINTEXT)
    print("  ciphertext:", ct.hex())

    _, forged = relay_tamper(nonce, ct, PLAINTEXT)
    print("\n[2] Relay modifies ciphertext (key never used)")
    print("  forged ct :", forged.hex())

    forged_pt = ctr(key, nonce, forged)
    c_xor = xor(ct, forged)
    p_xor = xor(PLAINTEXT, forged_pt)
    print("\n[3] XOR relation  C xor C' == P xor P'")
    print("  C xor C' :", c_xor.hex())
    print("  P xor P' :", p_xor.hex())
    print("  equal?   :", c_xor == p_xor)
    print("  READ xor WIPE =", xor(OLD, NEW).hex())

    print("\n[4] Receiver accepts forged ciphertext with no error")
    rx.process(nonce, forged)

    print("\n[5] Replay: same original ciphertext delivered twice")
    rx.process(nonce, ct)
    rx.process(nonce, ct)
    reads = sum(1 for c in rx.executed if c["action"] == "READ")
    print(f"  READ was processed {reads} times from one sender transmission")


if __name__ == "__main__":
    main()
