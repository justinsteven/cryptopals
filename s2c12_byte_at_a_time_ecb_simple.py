#!/usr/bin/env python3
import base64
import itertools
from secrets import token_bytes
from typing import Callable, Deque
from util import aes128_ecb_encrypt, chunkify
from collections import deque

"""
Byte-at-a-time ECB decryption (Simple)

Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK

Spoiler alert.

Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)

It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

Here's roughly how:

    Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
    Detect that the function is using ECB. You already know, but do this step anyways.
    Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
    Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
    Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
    Repeat for the next byte.

Congratulations.

This is the first challenge we've given you whose solution will break real crypto. Lots of people know that when you encrypt something in ECB mode, you can see penguins through it. Not so many of them can decrypt the contents of those ciphertexts, and now you can. If our experience is any guideline, this attack will get you code execution in security tests about once a year.
"""

BLOCK_SIZE = 16


class Aes128EcbAppendAndEncyptOracle:
    suffix: bytes
    key: bytes

    def __init__(self, suffix: bytes):
        self.key = token_bytes(BLOCK_SIZE)
        self.suffix = suffix

    def encrypt(self, prefix: bytes) -> bytes:
        return aes128_ecb_encrypt(prefix + self.suffix, key=self.key)


def discover_block_size_and_suffix_len_from_appending_oracle(oracle: Callable[[bytes], bytes]) -> tuple[int, int]:
    """
    >>> suffix = b"A"*8
    >>> oracle = Aes128EcbAppendAndEncyptOracle(suffix=suffix)
    >>> discover_block_size_and_suffix_len_from_appending_oracle(oracle.encrypt)
    (16, 8)

    >>> suffix = b"A"*24
    >>> oracle = Aes128EcbAppendAndEncyptOracle(suffix=suffix)
    >>> discover_block_size_and_suffix_len_from_appending_oracle(oracle.encrypt)
    (16, 24)
    """
    base_len_ct = len(oracle(b""))
    for i in itertools.count(1):
        new_len = len(oracle(b"Z"*i))
        if new_len != base_len_ct:
            block_size = new_len - base_len_ct
            suffix_len = new_len - block_size - i
            return block_size, suffix_len


def leak_suffix_from_appending_ecb_oracle(oracle: Callable[[bytes], bytes]):
    """
    >>> flag = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    >>> flag = base64.b64decode(flag.encode())
    >>> oracle = Aes128EcbAppendAndEncyptOracle(suffix=flag)
    >>> res = leak_suffix_from_appending_ecb_oracle(oracle.encrypt)
    >>> res == flag
    True
    """
    # Discover block size of oracle and the length of the suffix
    block_size, suffix_len = discover_block_size_and_suffix_len_from_appending_oracle(oracle)

    # Prove it's ECB, bail if it's not
    # TODO this fails to detect the case where the oracle prepends junk which starts with
    # two identical blocks of plaintext
    chunk = token_bytes(block_size)
    ct = list(chunkify(oracle(chunk*2), block_size))
    if ct[0] != ct[1]:
        raise ValueError("Oracle is not operating in ECB mode, or it's prepending junk")

    aligning_chunk = b"Z" * (block_size - (suffix_len % block_size))
    assert len(oracle(aligning_chunk[:-1])) + block_size == len(oracle(aligning_chunk)), "aligning chunk length is wrong"

    suffix: Deque[int] = deque()

    for i in range(1, suffix_len + 1):
        ct = oracle(aligning_chunk + b"Z"*i)
        last_chunk = list(chunkify(ct, block_size))[-1 - i // block_size]

        for b in range(256):
            pt = bytes([b, *suffix, *[block_size - i]*(block_size - i)][:block_size])
            ct = oracle(pt)
            if list(chunkify(ct, block_size))[0] == last_chunk:
                suffix.appendleft(b)
                break
        else:
            assert False, f"Failed... Got up to {bytes(suffix)!r}"

    return bytes(suffix)


def main():
    flag = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    flag = base64.b64decode(flag.encode())

    oracle = Aes128EcbAppendAndEncyptOracle(suffix=flag)
    res = leak_suffix_from_appending_ecb_oracle(oracle.encrypt)
    print(res.decode())


if __name__ == "__main__":
    main()
