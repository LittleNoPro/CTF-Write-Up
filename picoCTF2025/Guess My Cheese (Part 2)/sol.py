file = open("/home/team/CodePy/picoCTF2025/Guess My Cheese (Part 2)/cheese_list.txt", "r")
cheese_list = file.readlines()
cheese_list = [cheese.strip() for cheese in cheese_list]

from hashlib import sha256
from pwn import *
import hashlib


conn = remote("verbal-sleep.picoctf.net", 51325, level = 'debug')
conn.recvuntil(b"to guess it:  ")
enc = conn.recvline().strip().decode()

conn.sendafter(b"like to do?\n", "g\n")


def find_cheese(target):
    target = bytes.fromhex(target)

    for cheese in cheese_list:
        cheese = cheese.lower()
        cheese = cheese.encode()
        for salt in range(256):
            salt_res = salt
            salt = bytes([salt])

            for i in range(len(cheese) + 1):
                saltedcheese = cheese[:i] + salt + cheese[i:]

                if hashlib.sha256(saltedcheese).digest() == target:
                    return cheese, hex(salt_res)[2:].encode()

cheese, salt = find_cheese(enc)

conn.sendafter(b"So...what's my cheese?\n", cheese + b"\n")
conn.sendafter(b"Annnnd...what's my salt?\n", salt + b"\n")
conn.recvall()

# Flag: picoCTF{cHeEsY24ec2c20}