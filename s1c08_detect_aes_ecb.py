#!/usr/bin/env python3
from util import identify_ciphertexts_encrypted_with_ecb

"""
Detect AES in ECB mode

In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
"""


def main():
    with open("data/s1c08.txt", "r") as f:
        ciphertexts = [bytes.fromhex(line.rstrip()) for line in f.readlines()]

    block_size = 16

    suspected_ecb_ciphertexts = identify_ciphertexts_encrypted_with_ecb(ciphertexts, block_size=block_size)

    print("Suspected ECB ciphertexts:")
    for sus in suspected_ecb_ciphertexts:
        print(sus)


if __name__ == "__main__":
    main()
