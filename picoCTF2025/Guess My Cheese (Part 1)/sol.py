from pwn import *
from math import gcd
As = []
for i in range(26):
    if gcd(i, 26) == 1:
        As.append(i)


conn = remote("verbal-sleep.picoctf.net", 58487, level = 'debug')
conn.recvuntil(b"Here's my secret cheese -- if you're Squeexy, you'll be able to guess it:  ")
cheese = conn.recvline().decode().strip()

conn.recvuntil(b"What would you like to do?\n")
conn.sendline(b"e")
conn.sendafter(b"What cheese would you like to encrypt? ", b"CHEDDAR\n")
conn.recvuntil(b"Here's your encrypted cheese:  ")
ct = conn.recvline().decode().strip()
pt = "CHEDDAR"


A, B = -1, -1
for a in As:
    for b in range(26):
        text = ""
        for ch in ct:
            num = ord(ch) - ord('A')
            p = pow(a, -1, 26) * (num - b) % 26
            text += chr(p + ord('A'))
        if text == "CHEDDAR":
            A, B = a, b
            break
    if A != -1:
        break


guess_cheese = ""
for ch in cheese:
    num = ord(ch) - ord('A')
    p = pow(a, -1, 26) * (num - b) % 26
    guess_cheese += chr(p + ord('A'))

conn.recvuntil(b"What would you like to do?\n")
conn.sendline(b"g")
conn.recvuntil(b"So...what's my cheese?")
conn.sendline(guess_cheese.encode())

conn.recvall()