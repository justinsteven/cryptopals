#!/usr/bin/env python3
from util import pad_pkcs7

"""
Implement PKCS#7 padding

A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,

"YELLOW SUBMARINE"

... padded to 20 bytes would be:

"YELLOW SUBMARINE\x04\x04\x04\x04"
"""

"""
https://www.ibm.com/docs/en/zos/2.4.0?topic=rules-pkcs-padding-method says:

The rules for PKCS padding are very simple:

    Padding bytes are always added to the clear text before it is encrypted.
    Each padding byte has a value equal to the total number of padding bytes that are added. For example, if 6 padding bytes must be added, each of those bytes will have the value 0x06.
    The total number of padding bytes is at least one, and is the number that is required in order to bring the data length up to a multiple of the cipher algorithm block size.
"""


def main():
    plaintext = b"YELLOW SUBMARINE"
    padded = pad_pkcs7(plaintext, 20)
    print(padded)


if __name__ == "__main__":
    main()