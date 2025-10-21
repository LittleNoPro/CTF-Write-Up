import base64, re, zipfile
from pathlib import Path
from Crypto.Cipher import AES
import PyPDF2
from typing import Optional

BASE = Path("ctf")

# --- Share 1 (plain text) ---
x1, y1 = 1, int(open(BASE / "share1.txt").read().strip().split(",")[1])
print(x1, y1)

# --- Share 2 (Caesar cipher) ---
ciphertext2 = "71%779<<5=;5;<<799=55<>6;7696:959;888>8;<:"

def caesar_printable_decrypt(s: str, shift: int) -> str:
    out_chars = []
    for ch in s:
        idx = (ord(ch) - 32 - shift) % 95
        out_chars.append(chr(idx + 32))
    return ''.join(out_chars)

def find_best(cipher: str) -> Optional[tuple[int, str]]:
    pat = re.compile(r"^\s*2,\s*\d{20,}\s*$")
    for k in range(95):
        pt = caesar_printable_decrypt(cipher, k)
        if pat.search(pt):
            return pt
    return None

plaintext2 = find_best(ciphertext2)
x2, y2 = [int(x.strip()) for x in plaintext2.split(",")]
print(plaintext2)

# --- Share 3 (RSA PKCS#1 v1.5) ---
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
cipher = PKCS1_v1_5.new(RSA.import_key(open(BASE/"Share3/private_key.pem","rb").read()))
plain3 = cipher.decrypt(open(BASE/"Share3/encrypted_message.bin","rb").read(), b"X"*32).decode()
print(plain3)
x3, y3 = eval(plain3)  # "3, <int>"

# --- Share 4 (zip with password from SecretKey) ---
pwd = open(BASE/"SecretKey","r").read().strip().encode()
with zipfile.ZipFile(BASE/"share4.zip","r") as z:
    share4 = z.read("share4.txt", pwd=pwd).decode().strip("()")
print(share4)
x4, y4 = [int(x.strip()) for x in share4.split(",")]

# --- Share 5 (PDF: Vigenère mod 128 then base64) ---
pdf = PyPDF2.PdfReader(BASE/"share5.pdf"); pdf.decrypt("ctf_2025")
c = pdf.metadata["/Secret"].encode("latin-1")
key = b"ctf_2025"
pt_mod128 = bytes(((c[i] - key[i%len(key)]) % 128) for i in range(len(c)))
print(base64.b64decode(pt_mod128).decode())
x5, y5 = [int(x) for x in base64.b64decode(pt_mod128).decode().split(",")]

# --- Share 6 (trailing whitespace stego + XOR with 'ctf_2025') ---
raw_lines = open(BASE/"share6.py","rb").read().split(b"\n")
bits = []
for line in raw_lines:
    j = len(line)
    while j>0 and line[j-1] in (32,9):
        j -= 1
    trail = line[j:]
    for b in trail:
        bits.append('0' if b==32 else '1')
bitstr = ''.join(bits)
payload6 = bytes(int(bitstr[i:i+8],2) for i in range(0,len(bitstr)//8*8,8))
msg6 = bytes(payload6[i] ^ key[i%len(key)] for i in range(len(payload6)))
print(msg6)
x6, y6 = [int(x) for x in re.search(rb"6,\s*([0-9]+)", msg6).group(0).decode().split(",")]

p = int(open(BASE/"final/prime").read().strip())
shares = [(x1,y1),(x2, y2),(x3,y3),(x4,y4),(x5,y5),(x6,y6)]

def modinv(a,p): return pow(a,-1,p)
def lagrange_zero(shares,p):
    s=0
    for i,(xi,yi) in enumerate(shares):
        num=1; den=1
        for xj,_ in shares:
            if xj==xi: continue
            num = (num*(-xj))%p
            den = (den*(xi-xj))%p
        s = (s + yi * num * modinv(den,p)) % p
    return s

secret = lagrange_zero(shares, p)
key_bytes = secret.to_bytes(16,'big')

blob = base64.b64decode(open(BASE/"final/vault.enc","rb").read())
iv, ct = blob[:16], blob[16:]
pt = AES.new(key_bytes, AES.MODE_CBC, iv=iv).decrypt(ct)
print(pt)