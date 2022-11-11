import base64
import string


def hex2b64(hex: str) -> str:
    """
    >>> hex2b64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
    'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    """
    binary = bytes.fromhex(hex)
    return base64.b64encode(binary).decode()


def fixed_xor(b1: bytes, b2: bytes) -> bytes:
    """
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


def single_byte_xor(plaintext: bytes, key: int):
    """
    Return a variable length plaintext XOR'd with a given integer key
    Note: Trivially inlined if performance matters

    >>> single_byte_xor(b"\\x00\\x00\\x00", 0x41)
    b'AAA'
    >>> single_byte_xor(b"AAA", 0x41)
    b'\\x00\\x00\\x00'
    """
    assert 0 <= key < 256, "Key is out of range"
    return bytes(b ^ key for b in plaintext)


# https://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
en_char_frequencies = {
    "E": 12.02,
    "T": 9.10,
    "A": 8.12,
    "O": 7.68,
    "I": 7.31,
    "N": 6.95,
    "S": 6.28,
    "R": 6.02,
    "H": 5.92,
    "D": 4.32,
    "L": 3.98,
    "U": 2.88,
    "C": 2.71,
    "M": 2.61,
    "F": 2.30,
    "Y": 2.11,
    "W": 2.09,
    "G": 2.03,
    "P": 1.82,
    "B": 1.49,
    "V": 1.11,
    "K": 0.69,
    "X": 0.17,
    "Q": 0.11,
    "J": 0.10,
    "Z": 0.07,
}


def score_english_text_by_frequency(text: bytes) -> int:
    """
    Give a score for how English-like text is. Text may contain punctuation and non-printable chars. Punctuation
    is not scored. Non-printable chars are penalised.
    """
    len_text = len(text)

    printables = list(map(ord, string.printable))

    # TODO is this a good amount by which to punish non-printable chars?
    non_printable_char_punishment = 50
    score = 0

    for b in text:
        if b not in printables:
            score -= non_printable_char_punishment

    for c, expected_frequency in en_char_frequencies.items():
        c_upper = ord(c.upper())
        c_lower = ord(c.lower())

        expected_count = expected_frequency * len_text
        observed_count = text.count(c_upper) + text.count(c_lower)
        score -= (observed_count - expected_count)**2 / expected_count

    # TODO consider rewarding spaces per https://crypto.stackexchange.com/a/40930

    return score


def break_single_xor_cipher_en(ciphertext: bytes) -> bytes:
    """
    Use character frequency analysis to brute-force single byte XOR ciphertext

    >>> break_single_xor_cipher_en(bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
    b"Cooking MC's like a pound of bacon"
    """
    candidates = []
    for k in range(256):
        candidates.append(single_byte_xor(ciphertext, k))
    scored_candidates = {}
    for candidate in candidates:
        scored_candidates[candidate] = score_english_text_by_frequency(candidate)

    #from pprint import pprint
    #pprint([(k, v) for k, v in sorted(scored_candidates.items(), key=lambda x: x[1])])

    winner = sorted(scored_candidates.items(), key=lambda x: x[1])[-1]
    return winner[0]
