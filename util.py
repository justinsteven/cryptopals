import base64
from itertools import cycle
from math import inf
import string
from typing import List, Callable
from dataclasses import dataclass


def hex2b64(hex: str) -> str:
    """
    Decodes hex to bytes and returns a base64 representation of those bytes

    >>> hex2b64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
    'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    """
    binary = bytes.fromhex(hex)
    return base64.b64encode(binary).decode()


def fixed_xor(b1: bytes, b2: bytes) -> bytes:
    """
    Take two bytes arguments of equal length, return their XOR

    >>> arg1 = bytes.fromhex('1c0111001f010100061a024b53535009181c')
    >>> arg2 = bytes.fromhex('686974207468652062756c6c277320657965')
    >>> fixed_xor(arg1, arg2).hex()
    '746865206b696420646f6e277420706c6179'
    """
    assert len(b1) == len(b2), "Arguments are of different length"
    res = []
    for a, b in zip(b1, b2):
        res.append(a ^ b)
    return bytes(res)


def repeating_key_xor(plaintext: bytes, key: bytes) -> bytes:
    """
    Cycle the key, XOR plaintext with it, and return ciphertext

    >>> plaintext = b"Burning 'em, if you ain't quick and nimble\\nI go crazy when I hear a cymbal"
    >>> repeating_key_xor(plaintext, b"ICE").hex()
    '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    """
    res = []
    for a, b in zip(plaintext, cycle(key)):
        res.append(a ^ b)
    return bytes(res)


# https://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
en_char_frequencies = {'E': 0.1202, 'T': 0.091, 'A': 0.0812, 'O': 0.0768, 'I': 0.0731, 'N': 0.0695, 'S': 0.0628,
                       'R': 0.0602, 'H': 0.0592, 'D': 0.0432, 'L': 0.0398, 'U': 0.0288, 'C': 0.0271, 'M': 0.0261,
                       'F': 0.023, 'Y': 0.0211, 'W': 0.0209, 'G': 0.0203, 'P': 0.0182, 'B': 0.0149, 'V': 0.0111,
                       'K': 0.0069, 'X': 0.0017, 'Q': 0.0011, 'J': 0.001, 'Z': 0.0007999999999996898}


def score_english_text_by_frequency(text: bytes) -> float:
    """
    Give a score for how English-like text is. Text may contain punctuation and non-printable chars. Punctuation
    is not scored. Non-printable chars are penalised. Higher score means more English-like input
    """
    len_text = len(text)
    assert len_text > 10, "Total length of text is not great enough to give a meaningful score"

    printables = list(map(ord, string.printable))

    # TODO is this a good amount by which to penalise non-printable chars?
    # Should text be penalised exponentially more given higher incidence of non-printable chats? (thx atwolf0)
    non_printable_char_penalty = 50

    score = 0

    for b in text:
        if b not in printables:
            score -= non_printable_char_penalty

    penalties = {}

    for c, expected_frequency in en_char_frequencies.items():
        c_upper = ord(c.upper())
        c_lower = ord(c.lower())

        expected_count = expected_frequency * len_text
        observed_count = text.count(c_upper) + text.count(c_lower)
        penalty = chi_squared(observed_count, expected_count)

        penalties[c] = penalty

        score -= penalty

    # TODO consider rewarding spaces per https://crypto.stackexchange.com/a/4093

    return score


def chi_squared(observed_count: float, expected_count: float) -> float:
    """
    Return the chi squared test result for a given observed and expected count. If observed and expected are equal
    the chi squared test result is zero, else it increases as the delta between the counts increase. i.e. bigger
    number == worse match

    Pro tip: It's pronounced "kai" squared.

    https://en.wikipedia.org/wiki/Chi-squared_test

    >>> abs(chi_squared(90, 80.54) - 1.11) < .01
    True
    """
    if expected_count == 0:
        if observed_count == 0:
            return 1
        else:
            return inf
    return (observed_count - expected_count) ** 2 / expected_count


@dataclass
class ScoredDecryptionResult:
    plaintext: bytes
    ciphertext: bytes
    key: int
    score: float

    def __repr__(self):
        return f"ScoredDecryptionResult(plaintext={self.plaintext}, ciphertext={self.ciphertext}, key={self.key:#02x}, score={self.score:.2f})"


def break_single_xor_cipher(ciphertexts: List[bytes],
                            scoring_function: Callable = score_english_text_by_frequency) -> List[ScoredDecryptionResult]:
    """
    Use character frequency analysis to brute-force single-byte XOR ciphertexts

    Return ScoredDecryptionResult's sorted according to the scoring_function function

    >>> ciphertext = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    >>> break_single_xor_cipher([ciphertext])[0].plaintext
    b"Cooking MC's like a pound of bacon"

    >>> ciphertexts = [bytes.fromhex(line.strip()) for line in open("data/s1c4.txt", "r")]
    >>> any(b"jumping" in x.plaintext for x in break_single_xor_cipher(ciphertexts)[:10])
    True
    """
    decryptions: List[ScoredDecryptionResult] = []

    for ciphertext in ciphertexts:
        for k in range(256):
            plaintext = repeating_key_xor(ciphertext, bytes([k]))
            decryptions.append(ScoredDecryptionResult(plaintext=plaintext,
                                                      ciphertext=ciphertext,
                                                      key=k,
                                                      score=scoring_function(plaintext)))

    return sorted(decryptions, key=lambda x: x.score, reverse=True)
