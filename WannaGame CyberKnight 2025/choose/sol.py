from aes import *
from pwn import *

def dumb_step(s, key = None):
    pass

io = remote("ctf.cnsc.com.vn", 32928, level = 'debug')

plaintext1 = bytes([1, 2, 3, 4, 5, 6, 7, 8] + [0] * 8)
plaintext2 = bytes([1, 2, 3, 4, 5, 6, 7, 9] + [0] * 8)
plaintext3 = bytes([16, 16, 16, 16, 16, 16, 16, 17] + [16] * 8)
plaintext = plaintext1 + plaintext2 + plaintext3

def AES_without_AddRoundKey(plaintext, ciphertext):
    step = [dumb_step, sub_bytes, shift_rows, mix_columns]

    cipher = AES(bytes.fromhex("0" * 32))
    return cipher.encrypt_block_without_add_round_key(plaintext, step) == ciphertext

def check_diff(x, y):
    return sum([int(xx != yy) for xx, yy in zip(x, y)])

for _ in range(50):
    io.recvline()
    io.sendlineafter(b">>> ", plaintext.hex().encode())
    ciphertext = split_blocks(unhex(io.recvline().decode().strip()))

    if check_diff(ciphertext[0], ciphertext[1]) in [1, 4]:   # AES without MixColumns and ShiftRows
        io.sendlineafter(b">>> ", b"1")
    elif AES_without_AddRoundKey(plaintext1, ciphertext[0]):   # AES without AddRoundKey
        io.sendlineafter(b">>> ", b"1")
    elif xor(ciphertext[0], ciphertext[1], ciphertext[2]) == ciphertext[3]:   # AES withou SubBytes
        io.sendlineafter(b">>> ", b"1")
    else:
        io.sendlineafter(b">>> ", b"0")
    io.recvline()
io.recvall()

# W1{aAESEEESaEsaAEaSesEEEsAaseseesaSSEaaASeAAESEESSSaASeAsSSAAAAeAsE_vjRxMmX8jk}