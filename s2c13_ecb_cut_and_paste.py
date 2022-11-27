#!/usr/bin/env python3
from typing import Callable
from urllib.parse import parse_qsl, urlencode
from secrets import token_bytes
from util import aes128_ecb_encrypt, aes128_ecb_decrypt, chunkify
import itertools

"""
ECB cut-and-paste

Write a k=v parsing routine, as if for a structured cookie. The routine should take:

foo=bar&baz=qux&zap=zazzle

... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}

(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email address. You should have something like:

profile_for("foo@bar.com")

... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}

... encoded as:

email=foo@bar.com&uid=10&role=user

Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

    Encrypt the encoded user profile under the key; "provide" that to the "attacker".
    Decrypt the encoded user profile and parse it.

Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.
"""


def qs_to_dict(qs: str) -> dict:
    """
    >>> qs_to_dict("foo=bar&baz=qux&zap=zazzle")
    {'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle'}
    """
    return dict(parse_qsl(qs))


def email_to_qs(email: str, uid: int = 10, role: str = "user") -> str:
    """
    >>> email_to_qs("foo@bar.com")
    'email=foo%40bar.com&uid=10&role=user'

    >>> email_to_qs("foo@bar.com=&\\x0b")
    'email=foo%40bar.com%3D%26%0B&uid=10&role=user'
    """
    profile = {
        "email": email,
        "uid": uid,
        "role": role,
    }
    return urlencode(profile)


# AES-128
BLOCK_SIZE = 16


class ProfileOracle:
    key: bytes
    verbose: bool

    def __init__(self, verbose: bool = False):
        self.key = token_bytes(BLOCK_SIZE)
        self.verbose = verbose

    def encrypt(self, email: str) -> bytes:
        """
        Serialize email into a profile querystring, encrypt it using AES-128 ECB, and return it
        """
        profile_qs = email_to_qs(email)
        ct = aes128_ecb_encrypt(profile_qs.encode(), key=self.key)
        if self.verbose:
            print(f"Encrypt: {email!r} --> {profile_qs!r} --> {ct!r}")
        return ct

    def decrypt(self, encrypted_qs: bytes) -> str:
        """
        Decrypt using AES-128 ECB, deserialize to a dict, and return the dict's "role" value

        >>> oracle = ProfileOracle()
        >>> oracle.decrypt(oracle.encrypt("foo@bar.com"))
        'user'
        """
        pt = aes128_ecb_decrypt(encrypted_qs, key=self.key).decode()
        profile = qs_to_dict(pt)
        if self.verbose:
            print(f"Decrypt: {encrypted_qs!r} --> {pt!r} --> {profile}")
        return profile["role"]


def craft_profile_ct(oracle: Callable[[str], bytes], role: str) -> bytes:
    """
    >>> oracle = ProfileOracle()
    >>> profile = craft_profile_ct(oracle=oracle.encrypt, role="admin")
    >>> oracle.decrypt(profile)
    'admin'

    >>> profile = craft_profile_ct(oracle=oracle.encrypt, role="Z"*2)
    Traceback (most recent call last):
    ValueError: Role 'ZZ' must have a certain length or the attack fails

    >>> profile = craft_profile_ct(oracle=oracle.encrypt, role="Z"*20)
    Traceback (most recent call last):
    ValueError: Role 'ZZZZZZZZZZZZZZZZZZZZ' must have a certain length or the attack fails
    """
    if not 2 < len(role) < 17:
        raise ValueError(f"Role {role!r} must have a certain length or the attack fails")

    # Build a block that starts with the given role, and ends with '&uid=10&rol' (ish)
    b1 = " " * (BLOCK_SIZE - len("email="))
    b2 = role
    ct = oracle(b1 + b2)
    block_admin = list(chunkify(ct, BLOCK_SIZE))[1]

    # Build a block of all padding
    base_ct = oracle(b"")
    for i in itertools.count(1):
        ct = oracle(b" "*i)
        if len(base_ct) != len(ct):
            block_of_all_padding = list(chunkify(ct, BLOCK_SIZE))[-1]
            break

    # Find a padding_len such that a block ends with 'role='
    for padding_len in itertools.count(1):
        if len("email=" + " " * padding_len + "&uid=10&role=") % BLOCK_SIZE == 0:
            break

    ct = oracle(" "*padding_len)

    winning_ct = b"".join(list(chunkify(ct, BLOCK_SIZE))[:-1]) + block_admin + block_of_all_padding

    return winning_ct


def main():
    oracle = ProfileOracle()
    profile = craft_profile_ct(oracle=oracle.encrypt,
                               role="admin")
    role = oracle.decrypt(profile)
    print(f"Role: {role!r}")


if __name__ == "__main__":
    main()
