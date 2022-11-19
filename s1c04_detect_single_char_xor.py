#!/usr/bin/env python3
from util import break_single_xor_cipher

"""
Detect single-character XOR

One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)
"""


def main():
    with open("data/s1c04.txt", "r") as f:
        ciphertexts = [bytes.fromhex(line.strip()) for line in f]

    results = break_single_xor_cipher(ciphertexts)
    n = 10
    print(f"Top {n} results")
    for result in results[:n]:
        print(result)


if __name__ == "__main__":
    main()
