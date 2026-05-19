# elgamal-cpp

ElGamal asymmetric encryption implemented from scratch in C++98.
Built on top of the BigNum class from rsa-cpp, using OpenSSL BIGNUM internally.

## What's implemented

- `ElGamal` class:
  - `genpkey()` — generate key pair: prime p, generator g, private key x, public key y = g^x mod p
  - `encrypt(msg)` — returns ciphertext pair (c1, c2)
  - `decrypt(ciphertext)` — recover original message via c2 * c1^(-x) mod p
  - `text2bn` / `bn2text` — text <-> BigNum conversion

- Structs `EGKeyPair` and `EGCiphertext` with stream operators

## Build

```bash
make
```

Requires: GCC, OpenSSL (`-lcrypto`)

## Stack

C++98, OpenSSL BIGNUM, GNU Make, Linux
