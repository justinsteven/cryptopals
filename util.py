import base64
import itertools
from enum import Enum
from itertools import cycle
from math import inf
import string
from secrets import choice, token_bytes, randbelow
from typing import List, Callable, Generator, Tuple, Optional
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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

    >>> fixed_xor(b"AAAA", b"AAA")
    Traceback (most recent call last):
    ValueError: Arguments are of different length
    """
    if len(b1) != len(b2):
        raise ValueError("Arguments are of different length")
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

    >>> ciphertexts = [bytes.fromhex(line.strip()) for line in open("data/s1c04.txt", "r")]
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


def bitwise_hamming_distance(b1: bytes, b2: bytes) -> int:
    """
    Return the number of bits that must be changed in b1 to get b2

    >>> bitwise_hamming_distance(b"HELLO", b"JELLO")
    1
    >>> bitwise_hamming_distance(b"hello", b"jello")
    1
    >>> bitwise_hamming_distance(b"AAAAA", b"JJJJA")
    12
    >>> bitwise_hamming_distance(b"this is a test", b"wokka wokka!!!")
    37
    >>> bitwise_hamming_distance(b"AAAA", b"AAA")
    Traceback (most recent call last):
    ValueError: Inputs are of different length
    """
    if len(b1) != len(b2):
        raise ValueError("Inputs are of different length")
    res = 0
    for a, b in zip(b1, b2):
        x = a ^ b
        while x:
            res += x & 1
            x >>= 1
    return res


def chunkify(b: bytes, chunk_size: int) -> Generator[bytes, None, None]:
    """
    Yield chunk_size sized chunks from b

    >>> list(chunkify(b"ABCD", 2))
    [b'AB', b'CD']

    >>> list(chunkify(b"ABCDE", 2))
    [b'AB', b'CD', b'E']
    """
    for i in range(0, len(b), chunk_size):
        yield b[i:i + chunk_size]


def guess_repeating_xor_key_length(ciphertext: bytes) -> int:
    """
    Given a ciphertext which is the result of applying repeating XOR with an unknown key of unknown
    length. Guess the length of the key by chunking the ciphertext and observing inter-chunk hamming
    distances for chunks of all possible lengths

    Assumes len(key) <= (len(ciphertext) / 3)

    #>>> ciphertext = base64.b64decode(open("data/s1c06.txt", "r").read().encode())
    #>>> guess_repeating_xor_key_length(ciphertext)
    #29

    #>>> plaintext = open("data/alice.txt", "r").read()[:2048].encode()
    #>>> key = b"You wouldn't batch an RPC call"
    #>>> guess_repeating_xor_key_length(repeating_key_xor(plaintext, key)) == len(key)
    #True
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

    if not ciphertext:
        raise ValueError("ciphertext must be non-zero length")

    scores: List[Tuple[int, float]] = []

    for chunk_size in range(1, len(ciphertext) + 1):
        chunks = list(chunkify(ciphertext, chunk_size))
        # Throw away the last chunk in case it's incomplete
        chunks = chunks[:-1]
        # Check to see we have at least two chunks to work with
        if len(chunks) < 2:
            break
        score = 0
        num_comparisons = 0
        for a, b in itertools.combinations(chunks, 2):
            score += bitwise_hamming_distance(a, b)
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


def break_repeating_key_xor(ciphertext: bytes, key_length: Optional[int] = None) -> bytes:
    """
    Return the best-guess key for a ciphertext which has been encrypted using repeating key XOR

    @param ciphertext: The encrypted ciphertext
    @param key_length: (Optional) the key length, if known. If unknown, inter-chunk hamming distance will be used to derive it

    #>>> ciphertext = base64.b64decode(open("data/s1c06.txt", "r").read().encode())
    #>>> break_repeating_key_xor(ciphertext)
    #b'Terminator X: Bring the ioise'
    """
    if key_length is None:
        key_length = guess_repeating_xor_key_length(ciphertext)

    chunks = chunkify(ciphertext, key_length)

    transposed_chunks = [bytes(b for b in x if b is not None) for x in itertools.zip_longest(*chunks)]

    key: List[int] = []

    for transposed_chunk in transposed_chunks:
        key.append(break_single_xor_cipher([transposed_chunk])[0].key)

    return bytes(key)


def aes128_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128 in ECB mode using the given key

    Automatically unpads plaintext using PKCS#7

    >>> ciphertext = base64.b64decode(open("data/s1c07.txt", "r").read().encode())
    >>> b"You thought that I was weak, Boy, you're dead wrong" in aes128_ecb_decrypt(ciphertext, b"YELLOW SUBMARINE")
    True

    >>> aes128_ecb_decrypt(b"too short", key=bytes([0]*16))
    Traceback (most recent call last):
    ValueError: The length of the provided data is not a multiple of the block length.

    >>> aes128_ecb_decrypt(b"A"*16, key=b"too short")
    Traceback (most recent call last):
    ValueError: Invalid key size (72) for AES.
    """
    cipher = Cipher(algorithms.AES128(key), modes.ECB())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpad_pkcs7(plaintext)
    return plaintext


def aes128_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt ciphertext using AES-128 in ECB mode using the given key

    Automatically pads plaintext using PKCS#7

    >>> plaintext = b"Beware of hazardous materials"
    >>> key = b"YELLOW SUBMARINE"
    >>> aes128_ecb_decrypt(aes128_ecb_encrypt(plaintext, key), key) == plaintext
    True

    >>> aes128_ecb_encrypt(b"AAAA", key=b"too short")
    Traceback (most recent call last):
    ValueError: Invalid key size (72) for AES.
    """
    plaintext = pad_pkcs7(plaintext, 16)
    cipher = Cipher(algorithms.AES128(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def identify_ciphertexts_encrypted_with_ecb(ciphertexts: List[bytes], block_size: int) -> List[bytes]:
    """
    Given a list of ciphertexts, return the ciphertexts which were suspected to have been encrypted using
    a block cipher in ECB mode.

    This function assumes that _any_ redundancy on a block basis indicates ECB encryption.

    >>> ciphertexts = [bytes.fromhex(line.rstrip()) for line in open("data/s1c08.txt", "r").readlines()]
    >>> sus = identify_ciphertexts_encrypted_with_ecb(ciphertexts, 16)
    >>> len(sus)
    1
    >>> base64.b64encode(sus[0]).decode()
    '2IBhl0CooZt4QKijHIEKPQhkmvcNwG9P1dLWnHRM0oPi3QUva2Qdv50RsDSFQrtXCGSa9w3Ab0/V0tacdEzSg5R1yd/bwdRll5SdnH6Cv1oIZJr3DcBvT9XS1px0TNKDl6k+q41q7NVmSJFUeJprAwhkmvcNwG9P1dLWnHRM0oPUAxgMmMj22x8qP5xAQN6wq1GymTPywSPFg4awb7oYag=='
    """
    sus: List[bytes] = []
    for ciphertext in ciphertexts:
        chunks = list(chunkify(ciphertext, block_size))
        num_chunks = len(chunks)
        num_unique_chunks = len(set(chunks))
        num_duplicated_chunks = num_chunks - num_unique_chunks
        if num_duplicated_chunks > 0:
            sus.append(ciphertext)
    return sus


def pad_pkcs7(data: bytes, block_size: int) -> bytes:
    """
    >>> pad_pkcs7(b"YELLOW SUBMARINE", 20)
    b'YELLOW SUBMARINE\\x04\\x04\\x04\\x04'
    >>> pad_pkcs7(b"YELLOW SUBMARINE", 16)
    b'YELLOW SUBMARINE\\x10\\x10\\x10\\x10\\x10\\x10\\x10\\x10\\x10\\x10\\x10\\x10\\x10\\x10\\x10\\x10'
    >>> pad_pkcs7(b"YELLOW SUBMARINE", 17)
    b'YELLOW SUBMARINE\\x01'
    """
    num_padding_bytes = block_size - len(data) % block_size
    return data + bytes([num_padding_bytes] * num_padding_bytes)


class PaddingError(Exception):
    pass


def unpad_pkcs7(data: bytes, strict: bool = True) -> bytes:
    """
    >>> unpad_pkcs7(b"Hello, world!\\x02\\x02")
    b'Hello, world!'
    >>> unpad_pkcs7(pad_pkcs7(b"Beware of the hazmat", 100))
    b'Beware of the hazmat'
    >>> unpad_pkcs7(b"Hello, world!\\x02")
    Traceback (most recent call last):
    util.PaddingError: Bad padding in b'Hello, world!\\x02'
    """
    num_padding_bytes = data[-1]
    unpadded = data[:-1*num_padding_bytes]
    if strict:
        if any(b != num_padding_bytes for b in data[-1*num_padding_bytes:]):
            raise PaddingError(f"Bad padding in {data!r}")
    return unpadded


def aes128_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128 in CBC mode (the hard way) using the given key

    Automatically unpads plaintext using PKCS#7

    >>> ciphertext = base64.b64decode(open("data/s2c10.txt", "r").read().encode())
    >>> key = b"YELLOW SUBMARINE"
    >>> iv = bytes([0] * 16)
    >>> b"Play that funky music" in aes128_cbc_decrypt(ciphertext, key=key, iv=iv)
    True

    >>> aes128_cbc_decrypt(b"too short", key=bytes([0]*16), iv=bytes([0]*16))
    Traceback (most recent call last):
    ValueError: The length of the provided data is not a multiple of the block length.

    >>> aes128_cbc_decrypt(b"A"*16, key=b"too short", iv=bytes([0]*16))
    Traceback (most recent call last):
    ValueError: Invalid key size (72) for AES.

    # This actually blows up in fixed_xor before the Cipher gets a chance to complain
    # The important thing is, it blows up
    >>> aes128_cbc_decrypt(b"A"*16, key=bytes([0]*16), iv=b"too short")
    Traceback (most recent call last):
    ValueError: Arguments are of different length
    """
    def aes128_decrypt(ciphertext: bytes, key: bytes):
        cipher = Cipher(algorithms.AES128(key), modes.ECB())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    plaintext: List[bytes] = []
    prev_block = iv
    for chunk in chunkify(ciphertext, chunk_size=16):
        plaintext.append(fixed_xor(aes128_decrypt(chunk, key),
                                   prev_block))
        # Prepare to XOR this block into the next decryption operation
        prev_block = chunk

    return unpad_pkcs7(b"".join(plaintext))


def aes128_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Encrypt ciphertext using AES-128 in CBC mode (the hard way) using the given key

    Automatically pads plaintext using PKCS#7

    >>> key = b"YELLOW SUBMARINE"
    >>> iv = bytes([0] * 16)
    >>> plaintext = b"That's a lotta words, too bad I ain't reading em"
    >>> ciphertext = aes128_cbc_encrypt(plaintext, key=key, iv=iv)
    >>> aes128_cbc_decrypt(ciphertext, key=key, iv=iv) == plaintext
    True

    >>> aes128_cbc_encrypt(b"AAAA", key=b"too short", iv=bytes([0]*16))
    Traceback (most recent call last):
    ValueError: Invalid key size (72) for AES.

    # This actually blows up in fixed_xor before the Cipher gets a chance to complain
    # The important thing is, it blows up
    >>> aes128_cbc_encrypt(b"AAAA", key=bytes([0]*16), iv=b"too short")
    Traceback (most recent call last):
    ValueError: Arguments are of different length
    """
    def aes128_encrypt(plaintext: bytes, key: bytes):
        cipher = Cipher(algorithms.AES128(key), modes.ECB())
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()

    plaintext = pad_pkcs7(plaintext, 16)

    ciphertext: List[bytes] = []
    prev_block = iv
    for chunk in chunkify(plaintext, chunk_size=16):
        chunk = fixed_xor(chunk, prev_block)
        chunk_crypt = aes128_encrypt(chunk, key)
        prev_block = chunk_crypt
        ciphertext.append(chunk_crypt)

    return b"".join(ciphertext)


class BlockCipherMode(Enum):
    ECB = 0
    CBC = 1


class AES128EcbCbcOracle:
    """
    An oracle that randomly picks ECB or CBC mode (50/50 split) and then encrypts data using AES-128 in that mode
    using a random key (and random IV in the case of CBC mode), bookending the plaintext with 5-10 random bytes
    """
    mode: BlockCipherMode

    def __init__(self):
        if choice((True, False)):
            self.mode = BlockCipherMode.ECB
        else:
            self.mode = BlockCipherMode.CBC

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Bookend plaintext with 5-10 random bytes. Encrypt bookeneded plaintext with a random key (and a random IV
        in the case of CBC) using AES-128 with the cipher mode being self.mode (which is ECB 50% of the time and CBC
        the rest of the time). Return the ciphertext.
        """
        key = token_bytes(16)

        # Bookend plaintext with 5-10 random bytes
        plaintext = token_bytes(randbelow(6) + 5) + plaintext + token_bytes(randbelow(6) + 5)

        if self.mode is BlockCipherMode.ECB:
            return aes128_ecb_encrypt(plaintext, key=key)
        else:
            assert self.mode is BlockCipherMode.CBC, "What the hell happened here?"
            iv = token_bytes(16)
            return aes128_cbc_encrypt(plaintext, key=key, iv=iv)


def determine_oracle_ecb_vs_cbc(oracle: Callable) -> BlockCipherMode:
    """
    Determines if the callable oracle is encrypting using ECB or CBC

    Accounts for the fact that the oracle may be prepending a random number of random bytes

    >>> oracle = AES128EcbCbcOracle()
    >>> guessed_mode = determine_oracle_ecb_vs_cbc(oracle.encrypt)
    >>> guessed_mode is oracle.mode
    True
    """
    plaintext = b"A"*16*4

    ciphertext = oracle(plaintext)
    if identify_ciphertexts_encrypted_with_ecb([ciphertext], block_size=16):
        return BlockCipherMode.ECB
    else:
        return BlockCipherMode.CBC
