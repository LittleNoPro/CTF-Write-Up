import os
from pwn import xor

ROUND = 10
P = [12, 11, 8, 13, 5, 0, 6, 9, 15, 3, 1, 7, 10, 2, 4, 14]
KEY = os.urandom(16)

def pad(state):
    return state + bytes([16 - len(state) % 16]) * (16 - len(state) % 16)

def permute(state):
    new_state = b""
    for i in range(16):
        new_state += bytes([state[P[i]]])
    return new_state

def genroundkey(key):
    while True:
        new = b"\0"
        for i in [4, 2, 0, 6, 9, 14]:
            new = xor(new, key[i])
        key = key[1:] + new
        yield key


def encrypt():
    plaintext = pad(bytes.fromhex(input("Enter your plaintext in hex: ")))
    ciphertext = b""
    gen = genroundkey(KEY)
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        for _ in range(ROUND):
            block = permute(block)
            block = xor(block, next(gen))
        ciphertext += block
    print(ciphertext.hex())

def guess_the_key():
    guess = bytes.fromhex(input("Enter your guess: "))
    if guess == KEY:
        print(open("flag.txt", "r").read())
    else:
        exit(0)

def menu():
    print("""0. Encrypt\n1. Guess the key""")
    return int(input("> "))

while True:
    try:
        choice = [encrypt, guess_the_key]
        option = menu()
        choice[option]()
    except:
        print("Something wrong with your input...")
        exit(0)