from pwn import *

conn = remote("chall.lac.tf", 31180)
conn.recvuntil(b"Here's the encrypted flag in hex: \n")
flag_enc = conn.recvline().strip().decode()
flag_enc = bytes.fromhex(flag_enc)

for i in range(0, len(flag_enc), 16):
    conn.recvuntil(b"Enter as hex: ")
    payload = (flag_enc[i:i+16] + b"\x00" * (len(flag_enc) - 16))
    conn.sendline(payload.hex())
    data = conn.recvline().strip().decode()

    print(data[2:18], end = '')

# lactf{seems_it_was_extremely_convenient_to_get_the_flag_too_heh}