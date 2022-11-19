#!/usr/bin/env python3
import base64
from util import aes128_ecb_decrypt

"""
AES in ECB mode

The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

"YELLOW SUBMARINE".

(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
Do this with code.

You can obviously decrypt this using the OpenSSL command-line tool, but we're having you get ECB working in code for a reason. You'll need it a lot later on, and not just for attacking ECB.
"""


def main():
    with open("data/s1c07.txt", "r") as f:
        ciphertext = base64.b64decode(f.read().encode())

    key = b"YELLOW SUBMARINE"

    plaintext = aes128_ecb_decrypt(ciphertext, key)

    print(plaintext.decode())


if __name__ == "__main__":
    main()
