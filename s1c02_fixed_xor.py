#!/usr/bin/env python3
from util import fixed_xor

"""
Fixed XOR

Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c

... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965

... should produce:

746865206b696420646f6e277420706c6179
"""


def main():
    arg1 = bytes.fromhex('1c0111001f010100061a024b53535009181c')
    arg2 = bytes.fromhex('686974207468652062756c6c277320657965')
    res = fixed_xor(arg1, arg2)
    print(res.hex())


if __name__ == "__main__":
    main()
