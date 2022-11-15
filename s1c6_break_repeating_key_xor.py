#!/usr/bin/env python3
import base64
import itertools
from typing import Tuple, List

from util import repeating_key_xor


"""
Break repeating-key XOR
It is officially on, now.

This challenge isn't conceptually hard, but it involves actual error-prone coding. The other challenges in this set are there to bring you up to speed. This one is there to qualify you. If you can do this one, you're probably just fine up to Set 6.

There's a file here. It's been base64'd after being encrypted with repeating-key XOR.

Decrypt it.

Here's how:

    Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
    Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:

    this is a test

    and

    wokka wokka!!!

    is 37. Make sure your code agrees before you proceed.
    For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
    The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
    Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
    Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
    Solve each block as if it was single-character XOR. You already have code to do this.
    For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.

This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.
No, that's not a mistake.

We get more tech support questions for this challenge than any of the other ones. We promise, there aren't any blatant errors in this text. In particular: the "wokka wokka!!!" edit distance really is 37.
"""


def bitwise_hamming(b1: bytes, b2: bytes) -> int:
    """
    Return the number of bits that must be changed in b1 to get b2

    >>> bitwise_hamming(b"HELLO", b"JELLO")
    1
    >>> bitwise_hamming(b"hello", b"jello")
    1
    >>> bitwise_hamming(b"AAAAA", b"JJJJA")
    12
    >>> bitwise_hamming(b"this is a test", b"wokka wokka!!!")
    37
    """
    assert len(b1) == len(b2), "Inputs are of different length"
    res = 0
    for a, b in zip(b1, b2):
        x = a ^ b
        while x:
            res += x & 1
            x >>= 1
    return res


def guess_repeating_xor_key_length(ciphertext: bytes) -> int:
    """
    Given a ciphertext which is the result of applying repeating XOR with an unknown key of unknown
    length. Guess the length of the key by chunking the ciphertext and observing inter-chunk hamming
    distances for chunks of all possible lengths

    Assumes len(key) <= (len(ciphertext) / 3)

    >>> ciphertext = base64.b64decode(open("data/s1c6.txt", "r").read().encode())
    >>> guess_repeating_xor_key_length(ciphertext)
    29

    >>> plaintext = open("data/alice.txt", "r").read()[:2048].encode()
    >>> key = b"You wouldn't batch an RPC call"
    >>> guess_repeating_xor_key_length(repeating_key_xor(plaintext, key)) == len(key)
    True
    """

    """
    atwolf0: could you find the lowest common multiple in each pair going down the list and add
    up the most common of the common multiples and pick the one that has the most?
    
    atwolf0: only reason i thought pairs from the sorted list of results was because goign though every combonation
    might be too intensive. and since the list is already in order there should i think be a really obvious value
    pretty quickly
    
    atwolf0: just not sure the best way to actually explain it its like a list of a list of common multiples and pairs
    of the list sort of kinda made sense in my mind
    """

    assert ciphertext, "ciphertext must be non-zero-length"

    scores: List[Tuple[int, float]] = []

    for chunk_size in range(1, len(ciphertext) + 1):
        chunks = [ciphertext[i:i+chunk_size] for i in range(0, len(ciphertext), chunk_size)]
        # Throw away the last chunk in case it's incomplete
        chunks = chunks[:-1]
        # Check to see we have at least two chunks to work with
        if len(chunks) < 2:
            break
        score = 0
        num_comparisons = 0
        for a, b in itertools.combinations(chunks, 2):
            score += bitwise_hamming(a, b)
            num_comparisons += 1
        score /= num_comparisons
        score /= chunk_size
        scores.append((chunk_size, score))

    # Sort scores by score
    scores = sorted(scores, key=lambda x: x[1])

    def pairwise(iterable):
        # pairwise('ABCDEFG') --> AB BC CD DE EF FG
        a, b = itertools.tee(iterable)
        next(b, None)
        return zip(a, b)

    scores_deltas = []
    for a, b in pairwise(scores):
        scores_deltas.append((a[0], b[1] - a[1]))

    max_delta = 0
    index_of_max_delta = None

    for i, record in enumerate(scores_deltas):
        if record[1] > max_delta:
            max_delta = record[1]
            index_of_max_delta = i

    assert max_delta != 0, "Something went wrong"

    good_scores = scores[:index_of_max_delta+1]

    keysize = min(x[0] for x in good_scores)

    assert all(x[0] % keysize == 0 for x in good_scores), f"Not all good scores are multiples of the keysize {keysize}"

    return keysize


def break_repeating_key_xor(ciphertext: bytes) -> bytes:
    return b""


def main():
    with open("data/s1c6.txt", "r") as f:
        ciphertext = base64.b64decode(f.read().encode())

    keysize = guess_repeating_xor_key_length(ciphertext)
    print(f"Keysize: {keysize}")

    res = break_repeating_key_xor(ciphertext)
    print(res)


if __name__ == "__main__":
    main()
