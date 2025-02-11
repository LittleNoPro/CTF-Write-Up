from pwn import *

def PRG(s: bytes) -> bytes:
    assert len(s) == 2
    h = hashlib.new("sha3_256")
    h.update(s)
    return h.digest()[:4]

def xor_bytes(bytes1: bytes, bytes2: bytes) -> bytes:
    return bytes(b1 ^ b2 for b1, b2 in zip(bytes1, bytes2))

lookup_table = {}
for i in range(65536):
    seed = i.to_bytes(2, "big")
    lookup_table[PRG(seed)] = seed



conn = remote("chall.lac.tf", 31173, level = "debug")

for i in range(200):
    conn.recvuntil(b"Here's y: ")
    y = conn.recvline().strip().decode()
    y = binascii.unhexlify(y)

    com = b'v+\xa6\xa3'
    for key, value in lookup_table.items():
        if xor_bytes(y, key) in lookup_table:
            com = key
            break
    conn.sendafter(b"> ", com.hex() + "\n")
    conn.recvuntil(b'Did you commit the ')
    choice = b"beef" in conn.recvline().strip()

    if choice: # beef
        target = xor_bytes(y, com)
        if target in lookup_table:
            decom = lookup_table[target]
        else:
            decom = lookup_table[com]
    else: # chicken
        decom = lookup_table[com]

    conn.sendafter(b"> ", decom.hex() + "\n")
    conn.recvline()

# lactf{na0r_c0mm1tm3nt_sch3m3_but_wr0ng}