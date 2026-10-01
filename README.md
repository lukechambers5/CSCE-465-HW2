# CSCE 465/765 Homework 2: Protect Agent Messages with Classic Cryptography

This repository contains a CTR bit-flip/replay demo (Task 1), an authenticated finite-field Diffie-Hellman handshake (Task 2), an Encrypt-then-MAC record layer (Task 3), and adversarial tests (Task 4). The graded write-up is `report.pdf`.

## Files

| File | Purpose |
|---|---|
| `report.pdf` | The submission: answers, explanations, and evidence |
| `README.md` | Setup and run instructions (this file) |
| `AI_USAGE.md` | AI usage description |
| AI log file(s) | Exported AI conversation(s) |
| `baseline_ctr.py` | Task 1: AES-CTR without a MAC, bit-flip and replay demo |
| `handshake.py` | Task 2: authenticated ffdhe3072 handshake (RSA-PSS, SHA-256) |
| `secure_record.py` | Task 3: `seal()` / `open_record()` Encrypt-then-MAC record layer |
| `ffdhe3072.pem` | Diffie-Hellman group file generated in Lab Preparation |
| `tests/` | Task 4: pytest suite (`conftest.py`, `test_adversarial.py`, `test_limitations.py`) |

## Requirements

- Ubuntu 24.04 course VM (NAT network)
- Python 3 with `venv`
- OpenSSL 3.0 or newer (only needed to generate the group file)
- `cryptography==49.0.0` and `pytest==9.1.1`

## Setup

```bash
cd "$HOME/csce465-agentsec"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install cryptography==49.0.0 pytest==9.1.1
```

Generate the ffdhe3072 group file once (skip if `hw2/ffdhe3072.pem` already exists):

```bash
cd "$HOME/csce465-agentsec/hw2"
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe3072 -out ffdhe3072.pem
openssl dhparam -in ffdhe3072.pem -text -noout | head -3
```

The last command should print `DH Parameters: (3072 bit)` and `GROUP: ffdhe3072`.

## Running

Run everything from `hw2/` with the virtual environment active.

```bash
cd "$HOME/csce465-agentsec/hw2"
source ../.venv/bin/activate
```

**Task 1: CTR bit-flip and replay demo**

```bash
python baseline_ctr.py
```

Shows the original and forged ciphertext, the `C xor C' == P xor P'` relation, the receiver accepting the modified command, and the same ciphertext being processed twice.

**Task 2: authenticated handshake demo**

```bash
python handshake.py
```

Runs a successful handshake (both sides derive identical keys), then shows each attack being rejected: modified nonce, modified DH public value, unexpected identity, reflected hello, signature from the wrong RSA key, wrong peer public key, and a malformed transcript. Generating the RSA keys takes a few seconds. `handshake.py` loads `ffdhe3072.pem` from its own directory.

**Task 3: record layer demo**

```bash
python secure_record.py
```

Runs a handshake, exchanges records in both directions, and shows each tampering, replay, reflection, and reordering attempt being rejected.

**Task 4: tests**

```bash
python -m pytest tests -v
```

All tests should pass (29 tests). Each test asserts a specific exception (for example `AuthenticationFailure`, `ReplayError`, `WrongDirection`, or `HandshakeError`). `tests/conftest.py` adds `hw2/` to the import path, so run pytest from `hw2/`.

`tests/test_limitations.py` is not one of the required tests. It documents a limitation of the specified IV layout: for messages longer than 16 bytes, the CTR counter runs into the next sequence number's IV, so keystream blocks are reused across consecutive records.

## Design summary

- **Handshake:** each party signs `role || SHA-256(transcript)` with RSA-PSS. The transcript is length-prefixed (4-byte big-endian) and contains the protocol label, group, both identities, both DH public values, and both nonces. Keys are derived with the assignment's KDF, giving separate encryption and MAC keys per direction plus an 8-byte session ID.
- **Records:** `header || ciphertext || tag`, with `iv = session_id || sequence` and `tag = HMAC-SHA-256(K_mac, header || iv || ciphertext)`. The receiver checks structure, direction, MAC, then sequence, and only then decrypts. No plaintext is released after any error.
- **Libraries:** all cryptography uses the `cryptography` package. No RSA, SHA-256, HMAC, or DH arithmetic is implemented by hand.

## Notes

- Everything runs in-process on the local VM. No network sockets are used.
- Only fake data and harmless commands are used.
- AI assistance is documented in `AI_USAGE.md` and the accompanying log file(s).