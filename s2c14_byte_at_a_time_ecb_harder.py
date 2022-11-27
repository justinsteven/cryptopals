#!/usr/bin/env python3
import base64
import itertools
from secrets import token_bytes, randbelow
from typing import Callable, Deque, Tuple
from util import aes128_ecb_encrypt, chunkify
from collections import deque, namedtuple

"""
Byte-at-a-time ECB decryption (Harder)

Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

Same goal: decrypt the target-bytes.
Stop and think for a second.

What's harder than challenge #12 about doing this? How would you overcome that obstacle? The hint is: you're using all the tools you already have; no crazy math is required.

Think "STIMULUS" and "RESPONSE".
"""


BLOCK_SIZE = 16


class Aes128EcbAppendAndEncyptOracle:
    junk: bytes
    suffix: bytes
    key: bytes

    def __init__(self, suffix: bytes, prepended_junk_minmax: Tuple[int, int] = (0, 0)):
        self.key = token_bytes(BLOCK_SIZE)
        self.suffix = suffix
        junk_min, junk_max = prepended_junk_minmax
        if junk_min < 0:
            raise ValueError("junk_min must be >= 0")
        if junk_max < junk_min:
            raise ValueError("junk_max must be >= junk_min")
        self.junk = token_bytes(junk_min + randbelow(junk_max - junk_min + 1))

    def encrypt(self, prefix: bytes) -> bytes:
        return aes128_ecb_encrypt(self.junk + prefix + self.suffix, key=self.key)


Interrogation = namedtuple("Interrogation", ["block_size", "junk_length", "suffix_length"])


def interrogate_appending_oracle(oracle: Callable[[bytes], bytes]) -> Interrogation:
    """
    >>> suffix = b"A"*8
    >>> oracle = Aes128EcbAppendAndEncyptOracle(suffix=suffix)
    >>> interrogate_appending_oracle(oracle.encrypt)
    Interrogation(block_size=16, junk_length=0, suffix_length=8)

    >>> suffix = b"A"*24
    >>> oracle = Aes128EcbAppendAndEncyptOracle(suffix=suffix)
    >>> interrogate_appending_oracle(oracle.encrypt)
    Interrogation(block_size=16, junk_length=0, suffix_length=24)

    >>> suffix = b"A"*8
    >>> oracle = Aes128EcbAppendAndEncyptOracle(suffix=suffix, prepended_junk_minmax=(5, 10))
    >>> block_size, junk_length, suffix_length = interrogate_appending_oracle(oracle.encrypt)
    >>> block_size == 16
    True
    >>> junk_length == len(oracle.junk)
    True
    >>> suffix_length == len(suffix)
    True

    >>> oracle = Aes128EcbAppendAndEncyptOracle(suffix=suffix, prepended_junk_minmax=(40, 60))
    >>> block_size, junk_length, suffix_length = interrogate_appending_oracle(oracle.encrypt)
    >>> block_size == 16
    True
    >>> junk_length == len(oracle.junk)
    True
    >>> suffix_length == len(suffix)
    True
    """
    base_len_ct = len(oracle(b""))
    for j in itertools.count(1):
        new_len = len(oracle(b"Z"*j))
        if new_len != base_len_ct:
            block_size = new_len - base_len_ct
            junk_and_suffix_len = new_len - block_size - j
            break

    block = token_bytes(block_size)

    def pairwise(iterable):
        # pairwise('ABCDEFG') --> AB BC CD DE EF FG
        a, b = itertools.tee(iterable)
        next(b, None)
        return zip(a, b)

    def get_junk_len(oracle: Callable[[bytes], bytes], block_size: int) -> int:
        for i in range(block_size):
            padding = token_bytes(i)
            ct = oracle(padding + block * 2)
            ct_chunked = list(chunkify(ct, block_size))
            for j, (c1, c2) in enumerate(pairwise(ct_chunked)):
                if c1 == c2:
                    # We've managed to block-align our two 'block' blocks
                    # OR there is otherwise some adjacent block redundancy

                    # Check to see that the pairwise block redundancy was not caused by
                    # redundancy in the oracle's suffix
                    ct = oracle(token_bytes(i + block_size * 2))
                    ct_chunked = list(chunkify(ct, block_size))
                    if ct_chunked[j] != ct_chunked[j+1]:
                        # Confirmed
                        return block_size * j + (block_size - i) - block_size
        raise ValueError("Failed to determine junk len. oracle probably isn't ECB")

    junk_len = get_junk_len(oracle, block_size)

    return Interrogation(block_size=block_size,
                         junk_length=junk_len,
                         suffix_length=junk_and_suffix_len - junk_len)


def leak_suffix_from_appending_ecb_oracle(oracle: Callable[[bytes], bytes]):
    """
    >>> flag = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    >>> flag = base64.b64decode(flag.encode())
    >>> oracle = Aes128EcbAppendAndEncyptOracle(suffix=flag)
    >>> res = leak_suffix_from_appending_ecb_oracle(oracle.encrypt)
    >>> res == flag
    True

    >>> oracle = Aes128EcbAppendAndEncyptOracle(suffix=flag, prepended_junk_minmax=(5, 10))
    >>> res = leak_suffix_from_appending_ecb_oracle(oracle.encrypt)
    >>> res == flag
    True

    >>> oracle = Aes128EcbAppendAndEncyptOracle(suffix=flag, prepended_junk_minmax=(40, 60))
    >>> res = leak_suffix_from_appending_ecb_oracle(oracle.encrypt)
    >>> res == flag
    True
    """
    block_size, junk_len, suffix_len = interrogate_appending_oracle(oracle)

    aligning_chunk = b"Z" * (block_size - ((suffix_len + junk_len) % block_size))
    assert len(oracle(aligning_chunk[:-1])) + block_size == len(oracle(aligning_chunk)), "aligning chunk length is wrong"

    suffix: Deque[int] = deque()

    if junk_len % block_size == 0:
        # Special case because we've made a mess
        padding_exhaust_junk = b""
    else:
        padding_exhaust_junk = b"Y" * (block_size - (junk_len % block_size))

    for i in range(1, suffix_len + 1):
        ct = oracle(aligning_chunk + b"Z"*i)
        last_chunk = list(chunkify(ct, block_size))[-1 - i // block_size]

        for b in range(256):
            pt = padding_exhaust_junk + bytes([b, *suffix, *[block_size - i]*(block_size - i)][:block_size])
            ct = oracle(pt)
            if list(chunkify(ct, block_size))[(junk_len - 1) // block_size + 1] == last_chunk:
                suffix.appendleft(b)
                break
        else:
            assert False, f"Failed... Got up to {bytes(suffix)!r}"

    return bytes(suffix)


def main():
    flag = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    flag = base64.b64decode(flag.encode())

    for i in range(128):
        oracle = Aes128EcbAppendAndEncyptOracle(suffix=flag, prepended_junk_minmax=(i, i))
        assert len(oracle.junk) == i, "Oops"
        res = leak_suffix_from_appending_ecb_oracle(oracle.encrypt)
        assert res == flag, "Oops"


if __name__ == "__main__":
    main()
