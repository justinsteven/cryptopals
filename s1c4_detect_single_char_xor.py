#!/usr/bin/env python3
from typing import List

from util import break_single_xor_cipher_en, score_english_text_by_frequency

"""
Detect single-character XOR

One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)
"""


def find_single_char_xor_ciphertext_from_candidates(haystack: List[bytes]) -> bytes:
    """
    >>> candidates = [bytes.fromhex(line.strip()) for line in open("s1c4.txt", "r")]
    >>> find_single_char_xor_ciphertext_from_candidates(candidates)
    b'Now that the party is jumping\\n'
    """
    candidates = [break_single_xor_cipher_en(b) for b in haystack]

    scored_candidates = {}
    for candidate in candidates:
        scored_candidates[candidate] = score_english_text_by_frequency(candidate)

    #from pprint import pprint
    #pprint([(k, v) for k, v in sorted(scored_candidates.items(), key=lambda x: x[1])])

    winner = sorted(scored_candidates.items(), key=lambda x: x[1])[-1]
    return winner[0]


def main():
    with open("s1c4.txt", "r") as f:
        candidates = [bytes.fromhex(x.strip()) for x in f.readlines()]
    print(find_single_char_xor_ciphertext_from_candidates(candidates))


if __name__ == "__main__":
    main()
