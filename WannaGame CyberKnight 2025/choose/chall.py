from aes import *
import random
import os

def dumb_step(s, key = None):
    pass

key = os.urandom(16)
cipher = AES(key)
init_step = [add_round_key, sub_bytes, shift_rows, mix_columns]

for round in range(50):
    try:
        print(f"Round {round + 1}/50")
        plaintext = bytes.fromhex(input(">>> "))
        assert len(plaintext) <= 16 * 3, "Too long!"
        step = init_step[:]
        pos = random.randint(0, 3)
        step.pop(pos)
        step.insert(pos, dumb_step)
        bit = random.randint(0, 1)
        print(cipher.encrypt(plaintext, [init_step, step][bit]).hex())
        if int(input(">>> ")) != bit:
            print("Wrong!")
            exit(0)
        else:
            print("Correct!")
    except:
        exit(0)

print("Here is your flag !")
print(open("flag.txt", "r").read())
