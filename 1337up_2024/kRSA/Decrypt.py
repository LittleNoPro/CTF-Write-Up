from Crypto.Util.number import *
from pwn import *

def binary_search(r_possible, val):
    l, r = 0, len(r_possible) - 1
    while l <= r:
        mid = (l + r) // 2
        if r_possible[mid][1] == val:
            return r_possible[mid][0]
        if r_possible[mid][1] < val:
            l = mid + 1
        else:
            r = mid - 1
    return -1

def rsaMeetInTheMiddleAttack(e, n, ck, max_val):
    r_possible = []
    for r in range(1, max_val + 1):
        r_possible.append([r, (ck * inverse(pow(r, e, n), n)) % n])

    r_possible = sorted(r_possible, key=lambda x: x[1])

    for s in range(1, max_val + 1):
        r = binary_search(r_possible, pow(s, e, n))
        if r != -1:
            return (r * s) % n
    return 0


conn = remote("krsa.ctf.intigriti.io", 1346)

conn.recvuntil("n=")
n = int(conn.recvline().decode())

conn.recvuntil("e=")
e = int(conn.recvline().decode())

conn.recvuntil("ck=")
ck = int(conn.recvline().decode())

conn.recvuntil("?")

max_val = pow(2, 18)
k = rsaMeetInTheMiddleAttack(e, n, ck, max_val)
conn.sendline(str(k).encode())

flag = conn.recvline()
print(f"Flag is: {flag.decode()}")
