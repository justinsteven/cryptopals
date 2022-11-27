#!/usr/bin/env python3
import itertools
from secrets import token_bytes
from typing import Callable, List

from util import aes128_cbc_encrypt, aes128_cbc_decrypt, chunkify
from urllib.parse import quote, parse_qsl

"""
CBC bitflipping attacks

Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the string:

"comment1=cooking%20MCs;userdata="

.. and append the string:

";comment2=%20like%20a%20pound%20of%20bacon"

The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.

The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.

Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:

    Completely scrambles the block the error occurs in
    Produces the identical 1-bit error(/edit) in the next ciphertext block.

Stop and think for a second.

Before you implement this attack, answer this question: why does CBC mode have this property?
"""


BLOCK_SIZE = 16


class SandwichOracle:
    key: bytes
    verbose: bool

    def __init__(self, verbose: bool = False):
        self.key = token_bytes(BLOCK_SIZE)
        self.verbose = verbose

    def encrypt(self, userdata: bytes):
        """
        Take some userdata, sandwich it into the challenge's specified format, encrypt using AES-128 CBC
        with the Oracle's key and a random IV, return iv || ciphertext
        """
        pt = self.sandwich(userdata).encode()
        iv = token_bytes(BLOCK_SIZE)
        ct = aes128_cbc_encrypt(plaintext=pt,
                                key=self.key,
                                iv=iv)
        if self.verbose:
            print(f"{userdata!r} --> {pt!r} --> {iv+ct[:5]!r}...")
        return iv + ct

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        >>> oracle = SandwichOracle()
        >>> oracle.decrypt(oracle.encrypt(b"AAAA"))
        b'comment1=cooking%20MCs;userdata=AAAA;comment2=%20like%20a%20pound%20of%20bacon'
        """
        ct_chunks = list(chunkify(ciphertext, BLOCK_SIZE))
        iv, ct = ct_chunks[0], b"".join(ct_chunks[1:])
        pt = aes128_cbc_decrypt(ciphertext=ct,
                                key=self.key,
                                iv=iv)
        return pt

    def decrypt_and_parse(self, ciphertext: bytes) -> bool:
        """
        Take a ciphertext (iv||ct), decrypt it using AES-128 CBC with the Oracle's key, parse it, and return
        True if the plaintext's 'admin' is precisely "true", else return False

        >>> oracle = SandwichOracle()
        >>> oracle.decrypt_and_parse(oracle.encrypt(b"AAAA"))
        False
        """
        pt = self.decrypt(ciphertext)
        data = dict(parse_qsl(pt, separator=";"))
        if self.verbose:
            print(f"{ciphertext[:5]!r}... --> {pt!r} --> {data}")
        try:
            admin = data[b"admin"]
        except KeyError:
            # No "admin" key
            return False
        return admin == b"true"

    @staticmethod
    def sandwich(userdata: bytes) -> str:
        """
        >>> SandwichOracle.sandwich(b"AAAA")
        'comment1=cooking%20MCs;userdata=AAAA;comment2=%20like%20a%20pound%20of%20bacon'
        >>> SandwichOracle.sandwich(b"AAAA;foo=bar")
        'comment1=cooking%20MCs;userdata=AAAA%3Bfoo%3Dbar;comment2=%20like%20a%20pound%20of%20bacon'
        """
        prefix = "comment1=cooking%20MCs;userdata="
        suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
        data = prefix + quote(userdata) + suffix
        return data


def craft_ct_with_chosen_pt_prefix(encrypt_oracle: Callable[[bytes], bytes],
                                   decrypt_oracle: Callable[[bytes], bytes],
                                   prefix: bytes) -> bytes:
    if len(prefix) > BLOCK_SIZE:
        raise ValueError("Prefix is too long")

    ct = encrypt_oracle(b"")

    ct_chunks = list(chunkify(ct, BLOCK_SIZE))
    iv, ct = ct_chunks[0], b"".join(ct_chunks[1:])

    # Bitflip our chosen prefix into the IV
    pt = decrypt_oracle(iv + ct)
    pt_first_block = list(chunkify(pt, BLOCK_SIZE))[0]
    bitmask: List[int] = []
    crafted_iv: List[int] = []
    for a, b in zip(pt_first_block, prefix):
        bitmask.append(a ^ b)
    for a, b in itertools.zip_longest(bitmask, iv, fillvalue=0):
        crafted_iv.append(a ^ b)

    return bytes(crafted_iv) + ct


def main():
    oracle = SandwichOracle(verbose=True)
    ct = craft_ct_with_chosen_pt_prefix(encrypt_oracle=oracle.encrypt,
                                        prefix=b"admin=true;",
                                        decrypt_oracle=oracle.decrypt)
    is_admin = oracle.decrypt_and_parse(ct)
    print(f"Are we admin?: {is_admin}")


if __name__ == "__main__":
    main()
