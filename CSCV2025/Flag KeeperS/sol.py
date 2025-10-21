from pwn import *
from Crypto.Cipher import AES
import os

from sage.all import GF
x = GF(2)["x"].gen()
gf2e = GF(2 ** 128, name="y", modulus=x ** 128 + x ** 7 + x ** 2 + x + 1)

def _to_gf2e(n: int):
    return gf2e([(n >> i) & 1 for i in range(127, -1, -1)])

def _from_gf2e(p):
    n = p.polynomial().coefficients(sparse=False)
    ans = 0
    for i, c in enumerate(reversed(n)):
        if int(c) & 1:
            ans |= (1 << i)
    return ans & ((1 << 128) - 1)

def _ghash(h, a: bytes, c: bytes):
    la = len(a)
    lc = len(c)
    p = gf2e(0)
    for i in range(la // 16):
        p += _to_gf2e(int.from_bytes(a[16 * i:16 * (i + 1)], byteorder="big"))
        p *= h

    if la % 16 != 0:
        p += _to_gf2e(int.from_bytes(a[-(la % 16):] + bytes(16 - la % 16), byteorder="big"))
        p *= h

    for i in range(lc // 16):
        p += _to_gf2e(int.from_bytes(c[16 * i:16 * (i + 1)], byteorder="big"))
        p *= h

    if lc % 16 != 0:
        p += _to_gf2e(int.from_bytes(c[-(lc % 16):] + bytes(16 - lc % 16), byteorder="big"))
        p *= h

    p += _to_gf2e(((8 * la) << 64) | (8 * lc))
    p *= h
    return p

def aes_block_ecb(key: bytes, block16: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(block16)

def j0_from_nonce(nonce: bytes) -> bytes:
    assert len(nonce) == 12
    return nonce + b"\x00\x00\x00\x01"

def ctr_keystream_blocks(key: bytes, nonce: bytes, nblocks: int) -> bytes:
    J0 = int.from_bytes(j0_from_nonce(nonce), "big")
    out = b""
    for i in range(1, nblocks + 1):
        ctr = (J0 + i) & ((1 << 128) - 1)
        out += aes_block_ecb(key, ctr.to_bytes(16, "big"))
    return out

cur_idx = 0
io = remote('crypto1.cscv.vn', 1337)
io.recvuntil(b"Enter your choice")

def decrypt(enc_msg, key):
    nonce = enc_msg[:12]
    ct = enc_msg[12:-16]
    tag = enc_msg[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    msg = cipher.decrypt_and_verify(ct, tag)
    return msg

def rotate_server():
    global cur_idx
    io.sendline(b"1")
    io.recvuntil(b"current Server key: ")
    key_hex = io.recvline().strip().decode()
    key = bytes.fromhex(key_hex)
    cur_idx = (cur_idx + 16) % 256
    return key

def rotate_flagkeeper():
    global cur_idx
    io.sendline(b"2")
    io.recvuntil(b"current FlagKeeper key: ")
    key_hex = io.recvline().strip().decode()
    key = bytes.fromhex(key_hex)
    cur_idx = (cur_idx - 16) % 256
    return key

def ask_sign(enc_msg: bytes) -> bytes:
    io.sendline(b"3")
    io.sendlineafter(b"Enter the encrypted message (in hex): ", enc_msg.hex().encode())
    io.recvuntil(b"Signature (in hex): ")
    sig_hex = io.recvline().strip().decode()
    return bytes.fromhex(sig_hex)

def ask_flag(enc_msg: bytes, sig: bytes) -> str:
    io.sendline(b"4")
    io.sendlineafter(b"Enter the encrypted message (in hex): ", enc_msg.hex().encode())
    io.sendlineafter(b"Enter the signature (in hex): ", sig.hex().encode())
    io.recvuntil(b"Flag:")
    return io.recvline().strip().decode(errors="ignore")

def forge_tag(KS: bytes, KF: bytes, idx_sign=16, idx_flag=32):
    nonce = os.urandom(12)

    HS = aes_block_ecb(KS, b"\x00" * 16)
    HF = aes_block_ecb(KF, b"\x00" * 16)
    EJ0_S = aes_block_ecb(KS, j0_from_nonce(nonce))
    EJ0_F = aes_block_ecb(KF, j0_from_nonce(nonce))

    nblocks = 3
    S_S = ctr_keystream_blocks(KS, nonce, nblocks)
    S_F = ctr_keystream_blocks(KF, nonce, nblocks)
    Delta = bytes(a ^ b for a, b in zip(S_S, S_F))

    t_true  = b"admin = True"
    t_false = b"admin = False"
    assert len(t_true) <= 16 and len(t_false) <= 16

    PS_blk0 = bytearray(16)
    PS_blk0[:len(t_true)] = bytes([t_true[i] ^ Delta[i] for i in range(len(t_true))])
    for i in range(len(t_true), 16):
        PS_blk0[i] = ord('A')

    PS_blk1 = bytearray(16)
    PS_blk1[:len(t_false)] = t_false
    for i in range(len(t_false), 16):
        PS_blk1[i] = ord('B')

    PS_blk2 = bytearray(16)

    PS = bytes(PS_blk0 + PS_blk1 + PS_blk2)
    PF = bytes([PS[i] ^ Delta[i] for i in range(16 * nblocks)])

    assert b"admin = True" not in PS
    assert b"admin = False" in PS[idx_sign:idx_sign+16]
    assert b"admin = True" in PF[:idx_flag]
    assert b"admin = False" not in PF

    C_prefix = bytearray()
    C_prefix += bytes([PS[i]      ^ S_S[i]      for i in range(16)])
    C_prefix += bytes([PS[16 + i] ^ S_S[16 + i] for i in range(16)])

    hS = _to_gf2e(int.from_bytes(HS, "big"))
    hF = _to_gf2e(int.from_bytes(HF, "big"))
    gS0 = _ghash(hS, b"", bytes(C_prefix) + b"\x00" * 16)
    gF0 = _ghash(hF, b"", bytes(C_prefix) + b"\x00" * 16)

    HS2 = hS * hS
    HF2 = hF * hF
    HMIX = HS2 + HF2
    T0 = _to_gf2e(int.from_bytes(EJ0_S, "big") ^ int.from_bytes(EJ0_F, "big")) + gS0 + gF0

    B_gf = T0 * (HMIX**(-1))
    B = _from_gf2e(B_gf).to_bytes(16, "big")
    C = bytes(C_prefix) + B
    gS_full = _ghash(hS, b"", C)
    tag = (int.from_bytes(EJ0_S, "big") ^ _from_gf2e(gS_full)).to_bytes(16, "big")
    enc_msg = nonce + C + tag
    return enc_msg

KF = rotate_flagkeeper()
KS0 = rotate_server()
KS  = rotate_server()

enc_msg = forge_tag(KS, KF, idx_sign=16, idx_flag=16)
sig = ask_sign(enc_msg)
flag = ask_flag(enc_msg, sig)
print(flag)
