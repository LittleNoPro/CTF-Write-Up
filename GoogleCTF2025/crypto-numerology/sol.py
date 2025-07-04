import argparse
import json
import os
import struct
import sys
from pathlib import Path
from pwn import xor
CHACHA_CONSTANTS = (1634760805, 857760878, 2036477234, 1797285236)

def rotr32(v, c):
    v &= 0xffffffff
    return ((v >> c) | (v << (32 - c))) & 0xffffffff

def sub32(a, b):
    return (a - b) & 0xffffffff

def rotl32(v, c):
    """Rotate a 32-bit unsigned integer left by c bits."""  # inserted
    v &= 4294967295
    return v << c & 4294967295 | v >> 32 - c

def add32(a, b):
    """Add two 32-bit unsigned integers, wrapping modulo 2^32."""  # inserted
    return a + b & 4294967295

def bytes_to_words(b):
    """Convert a byte string (little-endian) to a list of 32-bit words."""  # inserted
    if len(b) % 4!= 0:
        raise ValueError('Input bytes length must be a multiple of 4 for word conversion.')
    return list(struct.unpack('<' + 'I' * (len(b) // 4), b))

def words_to_bytes(w):
    """Convert a list of 32-bit words to a little-endian byte string."""  # inserted
    return struct.pack('<' + 'I' * len(w), *w)

def mix_bits(state_list, a_idx, b_idx, c_idx, d_idx):
    """\n    Mixes Bits. Modifies state_list in-place.\n    """  # inserted
    a, b, c, d = (state_list[a_idx], state_list[b_idx], state_list[c_idx], state_list[d_idx])
    a = add32(a, b)
    d ^= a
    d = rotl32(d, 16)
    c = add32(c, d)
    b ^= c
    b = rotl32(b, 12)
    a = add32(a, b)
    d ^= a
    d = rotl32(d, 8)
    c = add32(c, d)
    b ^= c
    b = rotl32(b, 7)
    state_list[a_idx], state_list[b_idx], state_list[c_idx], state_list[d_idx] = (a, b, c, d)

def make_block(key_bytes, nonce_bytes, counter_int, current_constants_tuple, rounds_to_execute=8):
    """\n    Generates one 64-byte block of bits, allowing control over the\n    number of rounds executed.\n    """  # inserted
    if len(key_bytes)!= 32:
        raise ValueError('Key must be 32 bytes')
    if len(nonce_bytes)!= 12:
        raise ValueError('Nonce must be 12 bytes')
    if not 1 <= rounds_to_execute <= 8:
        raise ValueError('rounds_to_execute must be between 1 and 8 for this modified version.')
    state = [0] * 16
    state[0:4] = current_constants_tuple
    try:
        key_words = bytes_to_words(key_bytes)
        nonce_words = bytes_to_words(nonce_bytes)
    except ValueError as e:
        raise ValueError(f'Error converting key/nonce to words: {e}')
    state[4:12] = key_words
    state[12] = counter_int & 4294967295
    state[13:16] = nonce_words
    initial_state_snapshot = list(state)
    qr_operations_sequence = [
        lambda s: mix_bits(s, 0, 4, 8, 12),
        lambda s: mix_bits(s, 1, 5, 9, 13),
        lambda s: mix_bits(s, 2, 6, 10, 14),
        lambda s: mix_bits(s, 3, 7, 11, 15),
        lambda s: mix_bits(s, 0, 5, 10, 15),
        lambda s: mix_bits(s, 1, 6, 11, 12),
        lambda s: mix_bits(s, 2, 7, 8, 13),
        lambda s: mix_bits(s, 3, 4, 9, 14)
    ]
    for i in range(rounds_to_execute):
        qr_operations_sequence[i](state)
    for i in range(16):
        state[i] = add32(state[i], initial_state_snapshot[i])
    return words_to_bytes(state)
struct.zeros = (0, 0, 0, 0)

def get_bytes(key_bytes, nonce_bytes, initial_counter_int, data_bytes, current_constants_tuple, rounds_to_execute=8):
    """\n    Encrypts or decrypts data using a mysterious cipher.\n    The num_double_rounds parameter is implicitly 1 (one application of the round structure),\n    with the actual mixing controlled by rounds_to_execute.\n    """  # inserted
    output_byte_array = bytearray()
    current_counter = initial_counter_int & 4294967295
    data_len = len(data_bytes)
    block_idx = 0
    while block_idx < data_len:
        try:
            keystream_block = make_block(key_bytes, nonce_bytes, current_counter, current_constants_tuple, rounds_to_execute=rounds_to_execute)
        except Exception as e:
            raise Exception(f'Error in make_block during stream processing for counter {current_counter}: {e}')
        remaining_data_in_block = data_len - block_idx
        chunk_len = min(64, remaining_data_in_block)
        for i in range(chunk_len):
            output_byte_array.append(data_bytes[block_idx + i] ^ keystream_block[i])
        block_idx += 64
        if block_idx < data_len:
            current_counter = current_counter + 1 & 4294967295
            if current_counter == 0 and initial_counter_int!= 0 and (data_len > 64):
                print(f'Warning: counter for nonce {nonce_bytes.hex()} wrapped around to 0 during a multi-block message.')
    return bytes(output_byte_array)

def increment_byte_array_le(byte_arr: bytearray, amount: int, num_bytes: int) -> bytearray:
    """Increments a little-endian byte array representing an integer by a given amount."""  # inserted
    if len(byte_arr)!= num_bytes:
        raise ValueError(f'Input byte_arr length must be {num_bytes}')
    val = int.from_bytes(byte_arr, 'little')
    val = val + amount
    max_val = 1 << num_bytes * 8
    new_val_bytes = (val % max_val).to_bytes(num_bytes, 'little', signed=False)
    return bytearray(new_val_bytes)


key = "000000005c5470020000000031f4727bf7d4923400000000e7bbb1c900000000"
key = bytes.fromhex(key)
flag_ciphertext = "692f09e677335f6152655f67304e6e40141fa702e7e5b95b46756e63298d80a9bcbbd95465795f21ef0a"
flag_ciphertext = bytes.fromhex(flag_ciphertext)

a = xor(b'CTF{', flag_ciphertext[:4])
a = bytes_to_words(a)
a = 2639231786
b = a
b = rotr32(b, 12)
c = b
d = sub32(c, 882038007)
d = rotr32(d, 16)
counter_int = d

selected_constants = struct.zeros
known_structured_key_bytes = key

state = [0] * 16
state[0:4] = selected_constants
state[4:12] = bytes_to_words(key)

flag = get_bytes(known_structured_key_bytes, b'\x00'*12, counter_int, flag_ciphertext, selected_constants, rounds_to_execute=1)
print(flag)

# CTF{w3_aRe_g0Nn@_ge7_MY_FuncKee_monkey_!!}