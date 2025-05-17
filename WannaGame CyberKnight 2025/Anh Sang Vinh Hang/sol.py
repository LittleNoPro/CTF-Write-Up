from base64 import b64decode
from itertools import *
from string import ascii_letters
from pwn import xor

message = "kOKO1fZJVp1Im90chpvtwdnCHwArCEEdJSt41fZJTLlaIMdCR+Ppj9ODA+PmBwZPslNBm/OqkzaGm92P3LEhwdfWs5QpSRWOfwOPm+WImvmIm9oBCUdoiXgDHkhrSQ8HAiDB0/AAADUAAR4aR0OpWhzCUE2m0vgb5FRwWir6Tj/Bw9xAR2sgiJtg0U4vSRKsZf6Gm/2qijbB1c6t00lkwdlgw04gSRWOfwGIm/2Imu+P3IkChpr1wdjLkZvaSaX+JStC0r1JTjAnC4kDhpvRlZvNF+b3iNryrbCDWivITniV00jUwE1ojVoZx04gSQKOfzeAm+UBweN80okJDkEmz5voGElnC6LcqvfBz3DSsTHB1c6P3JFolclCy6trSaLOqvjByFLITj/B0MGt004vwdNCy6FnCwiOfi+Pm/yImv2Vl4kDpIBoIhnOUFQviNvIqbAnC1fITXiMWhPJCgxogtNCy71nrfCOfzOIm/oBT7lbGMcGR0sgAAEMEwCD+IDUR7CDWirCTj/B12rECQAlAAECHkhnBIDVebCJfTAHADqA1IkJDsHzfJvLkZr4HU9PhlNMm/yImvWVm9+P3KFokloYwQAzAYDVaeTB2HDShznBzWzHR1Q6AAAGUEsvqtUBo7CR03DTgzHB12rOR+Ppj9ODA+PmBwZPrPGYm/OqkzaGm92P3LEhzZvOs4BnBaLP5OMAACBJRzGA1IkGhpvrkZvEGcH8xgBPp/giAf8ODHiG0kjV9k4vwdXLtpBnGQmsbeDBz/6qgTbB08CP3Kc9wX8ykZvWAEEXJStI1fZJCACu6YBOEcHyTMKDkqDUSQ+pZfnB1lLJACsAABhOE8HzctWDBMH9yAhPp3FaHPBJTblaIt1OBePij5vIGOPzBwZPqP8AATAAACyTWhLFR0KLS9WDG0kmRUECBzDBz3DTgTfB1WrECQAlAAA6BAA0iNre5PMiGf9JQrlbCscJR1Qhj9ODBMH91kEZBzDB2VLEALlbEsdAR3aLQZvABcH8+AhPp1NY1fZJTJtBm8qP3L1yweySC2h2WhQwoKaI5MkcTmG+3stZX0Z60IzBFUIiXlZY8aKD3vMU"

def hamming(s1, s2):
    s1_bin = "".join([format(byte, "08b") for byte in s1])
    s2_bin = "".join([format(byte, "08b") for byte in s2])

    d = 0
    for bit1, bit2 in zip(s1_bin, s2_bin):
        if bit1 != bit2:
            d += 1
    return d

def key_score(ciphertext, key_size):
    ciphertext_blocks = [ciphertext[i:i+key_size] for i in range(0, len(ciphertext), key_size)]
    ciphertext_blocks_pairs = list(combinations(ciphertext_blocks, 2))
    avg = sum(hamming(block1, block2) for block1, block2 in ciphertext_blocks_pairs) / len(ciphertext_blocks_pairs)
    return avg / key_size

def guess_key_size(ciphertext):
    key_sizes = range(2, 40) # this range should be enough
    key_scores = [(key_size, key_score(ciphertext, key_size)) for key_size in key_sizes]
    return sorted(key_scores, key = lambda x: x[1])[0][0]

ciphertext = b64decode(message)
key_size = guess_key_size(ciphertext)




# frequencies of the letters in English
# source: https://en.wikipedia.org/wiki/Letter_frequency
frequencies = {
    'a': 0.082,
    'b': 0.015,
    'c': 0.028,
    'd': 0.043,
    'e': 0.13,
    'f': 0.022,
    'g': 0.02,
    'h': 0.061,
    'i': 0.07,
    'j': 0.0015,
    'k': 0.0077,
    'l': 0.04,
    'm': 0.024,
    'n': 0.067,
    'o': 0.075,
    'p': 0.019,
    'q': 0.00095,
    'r': 0.06,
    's': 0.063,
    't': 0.091,
    'u': 0.028,
    'v': 0.0098,
    'w': 0.024,
    'x': 0.0015,
    'y': 0.02,
    'z': 0.00074
}

def transpose(ciphertext, keysize):
    blocks = [ciphertext[i:i+keysize] for i in range(0, len(ciphertext), keysize)]
    transposed = [bytes([block[i] for block in blocks if i < len(block)]) for i in range(keysize)] # transpose the blocks into other blocks of each nth bit of the blocks. this means each block will be all the character xored by once single byte of the key, so we can do statistics on the block to guess the right key byte that was the most probably used
    return transposed

def repeating_key_xor(key, plaintext):
    return xor(bytes(islice(cycle(key), len(plaintext))), plaintext)

def score_text(text):
    score = 0
    for letter, freq in frequencies.items():
        freq_actual = text.count(ord(letter)) / len(text)
        score += abs(freq - freq_actual)

    for letter in text:
        if letter not in (" " + ascii_letters).encode():
            score += 1 # big malus for everything that is not a letter or a space, because the text is probably containing almost only these characters

    return score

def crack_xor_cipher(ciphertext):
    guesses = []

    for possible_key in range(256):
        key = bytes([possible_key]) * len(ciphertext)
        plaintext = xor(ciphertext, key)
        score = score_text(plaintext)
        guesses.append((score, bytes([possible_key])))

    return min(guesses, key = lambda x: x[0])[1]

def crack_repeating_key_xor(ciphertext, key_size):
    transposed = transpose(ciphertext, key_size)
    key = b""
    for block in transposed:
        key += crack_xor_cipher(block)
    return key

ciphertext = b64decode(message)

key = crack_repeating_key_xor(ciphertext, key_size)
plaintext = repeating_key_xor(key, ciphertext)

print(f"Key = {key.decode()}")
print(f"Plaintext = {plaintext.decode()}")


# W1{H13u_d6i_Xun9_eb78f217bebe77752beb}