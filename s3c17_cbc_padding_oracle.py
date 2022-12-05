#!/usr/bin/env python3
import base64
from secrets import choice, token_bytes
from typing import Callable, Deque, List, Optional
from collections import deque
from util import aes128_cbc_decrypt, aes128_cbc_encrypt, chunkify, PaddingError, fixed_xor, unpad_pkcs7

"""
The CBC padding oracle

This is the best-known attack on modern block-cipher cryptography.

Combine your padding code and your CBC code to write two functions.

The first function should select at random one of the following 10 strings:

MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93

... generate a random AES key (which it should save for all future encryptions), pad the string out to the 16-byte AES block size and CBC-encrypt it under that key, providing the caller the ciphertext and IV.

The second function should consume the ciphertext produced by the first function, decrypt it, check its padding, and return true or false depending on whether the padding is valid.
What you're doing here.

This pair of functions approximates AES-CBC encryption as its deployed serverside in web applications; the second function models the server's consumption of an encrypted session token, as if it was a cookie.

It turns out that it's possible to decrypt the ciphertexts provided by the first function.

The decryption here depends on a side-channel leak by the decryption function. The leak is the error message that the padding is valid or not.

You can find 100 web pages on how this attack works, so I won't re-explain it. What I'll say is this:

The fundamental insight behind this attack is that the byte 01h is valid padding, and occur in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.

02h in isolation is not valid padding.

02h 02h is valid padding, but is much less likely to occur randomly than 01h.

03h 03h 03h is even less likely.

So you can assume that if you corrupt a decryption AND it had valid padding, you know what that padding byte is.

It is easy to get tripped up on the fact that CBC plaintexts are "padded". Padding oracles have nothing to do with the actual padding on a CBC plaintext. It's an attack that targets a specific bit of code that handles decryption. You can mount a padding oracle on any CBC block, whether it's padded or not.
"""


BLOCK_SIZE = 16


class CBCPaddingOracle:
    pt: bytes
    key: bytes

    def __init__(self, pt: bytes):
        self.pt = pt
        self.key = token_bytes(BLOCK_SIZE)

    def encrypt(self) -> bytes:
        iv = token_bytes(BLOCK_SIZE)
        ct = aes128_cbc_encrypt(plaintext=self.pt,
                                key=self.key,
                                iv=iv)
        return iv + ct

    def decrypt_and_check_padding(self, ct: bytes) -> bool:
        ct_chunks = list(chunkify(ct, BLOCK_SIZE))
        iv, ct = ct_chunks[0], b"".join(ct_chunks[1:])
        try:
            aes128_cbc_decrypt(ciphertext=ct,
                               key=self.key,
                               iv=iv)
        except PaddingError:
            return False
        return True


class PaddingOracleAttackError(Exception):
    pass


# TODO explore the case where the PKCS#7 unpadder allows the trailing byte to be \x00.
# In my experience this causes many padding oracle attack tools to fail.
# Can we work around this? I think our recursive way of working sets us up really nicely to be able to.

def leak_pt_from_padding_oracle(oracle: Callable[[bytes, bytes], bool], iv: bytes, ct: bytes) -> bytes:
    """
    @param oracle: A function which takes an IV and a ciphertext and returns True if the PKCS#7 padding was correct, else False
    @param iv: A known-good IV
    @param ct: A known-good ciphertext
    @return: The plaintext corresponding to IV and ciphertext

    >>> flag = b"Hack the planet"
    >>> oracle = CBCPaddingOracle(flag)
    >>> ct = oracle.encrypt()
    >>> ct_chunks = list(chunkify(ct, BLOCK_SIZE))
    >>> iv, ct = ct_chunks[0], b"".join(ct_chunks[1:])
    >>> pt = leak_pt_from_padding_oracle(oracle=lambda iv, ct: oracle.decrypt_and_check_padding(iv + ct), iv=iv, ct=ct)
    >>> pt == flag
    True
    """
    if not oracle(iv, ct):
        raise ValueError(f"Oracle is returning False for iv={iv!r}, ct={ct!r}. Bad oracle, or bad IV/ct")

    ct_chunks = list(chunkify(ct, BLOCK_SIZE))

    def attack_block(oracle: Callable[[bytes, bytes], bool],
                     block: bytes,
                     zeroing_iv: Optional[Deque[int]] = None) -> bytes:
        """
        @param oracle: A CBC padding oracle that returns True given good padding else False
        @param block: A block of CBC ciphertext
        @param zeroing_iv: The zeroing IV constructed so far (or None if it's the start of a fresh attack)
        @return: The zeroing IV of the block of ciphertext
        """
        zeroing_iv = zeroing_iv if zeroing_iv is not None else deque()
        block_size = len(block)

        prefix = bytes(block_size - len(zeroing_iv) - 1)
        suffix = bytes(b ^ (len(zeroing_iv) + 1) for b in zeroing_iv)
        spikes: List[int] = []
        for j in range(256):
            spiked_iv = prefix + bytes([j]) + suffix
            padding_is_correct = oracle(spiked_iv, block)
            if padding_is_correct:
                spikes.append(j)
        if len(spikes) == 1:
            zeroing_iv.appendleft(spikes[0] ^ (len(zeroing_iv) + 1))
            if len(zeroing_iv) == block_size:
                return bytes(zeroing_iv)
            return attack_block(oracle, block, zeroing_iv=zeroing_iv)
        elif len(spikes) == 2 and len(zeroing_iv) == 0:
            # Hit the quirky case where block[-2] == 2, or block[-3:-1] == 3, 3, or ...
            # We need to disambiguate
            # Note that there's an easier way to do this, but this does work
            try:
                # Try the first spike
                return attack_block(oracle, block, zeroing_iv=deque([spikes[0]]))
            except PaddingOracleAttackError:
                # Try the other spike
                return attack_block(oracle, block, zeroing_iv=deque([spikes[1]]))
        else:
            raise PaddingOracleAttackError(f"Failed to attack oracle over the given block: {block!r}")

    zeroing_ivs = [attack_block(oracle, block) for block in ct_chunks]
    pt: List[bytes] = []

    for a, b in zip([iv, *ct_chunks[:-1]], zeroing_ivs):
        pt.append(fixed_xor(a, b))

    return unpad_pkcs7(b"".join(pt))


def main():
    # Pick a line from the challenge input
    with open("data/s3c17.txt", "r") as f:
        lines = list(map(lambda x: x.strip(), f.readlines()))

    flag = base64.b64decode(choice(lines).encode())

    oracle = CBCPaddingOracle(pt=flag)
    ct = oracle.encrypt()
    chunks = list(chunkify(ct, BLOCK_SIZE))
    iv, ct = chunks[0], b"".join(chunks[1:])

    def wrapped_oracle(iv: bytes, ciphertext: bytes) -> bool:
        return oracle.decrypt_and_check_padding(iv + ciphertext)

    pt = leak_pt_from_padding_oracle(oracle=wrapped_oracle, iv=iv, ct=ct)

    print(pt)


if __name__ == "__main__":
    main()
