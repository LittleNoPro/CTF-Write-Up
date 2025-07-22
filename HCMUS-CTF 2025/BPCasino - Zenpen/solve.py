from pwn import *

# io = process(['python3', '/home/team/CodePy/HCMUS-CTF/BPCasino - Zenpen/chall.py'], level='debug')
io = remote('chall.blackpinker.com', 33546)

last = b''
for _ in range(3 * 37):
    msg = b'\x00' * ((_ + 1) * 16)
    io.sendlineafter(b'Plaintext (hex) ', msg.hex())
    ct = io.recvline().strip().decode()
    ct = bytes.fromhex(ct)
    if _ == 0:
        io.sendlineafter(b'Guess what? ', str('1').encode())
        last = ct[:16]
        continue

    if ct[:16] == last:
        io.sendlineafter(b'Guess what? ', str('1').encode())
    else:
        io.sendlineafter(b'Guess what? ', str('0').encode())


flag = io.recvline().strip().decode()
print(flag)

# HCMUS-CTF{g3tting_st4rted_w1th_CBC}