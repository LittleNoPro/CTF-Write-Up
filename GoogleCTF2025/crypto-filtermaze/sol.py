from pwn import *
import subprocess
import re
import tempfile
import os
import json
from sage.all import *
from sage.modules.free_module_integer import IntegerLattice
import json

p = remote("filtermaze.2025.ctfcompetition.com", 1337, level='debug')

pow_prompt = p.recvuntil(b"Solution?").decode()
challenge_id = re.search(r"solve (s\.[^\s]+)", pow_prompt).group(1)
with tempfile.NamedTemporaryFile("w+", delete=False) as tmpf:
    tmpf.write(subprocess.check_output(["curl", "-sSL", "https://goo.gle/kctf-pow"]).decode())
    tmpf.flush()
    pow_script_path = tmpf.name
solution = subprocess.check_output(["python3", pow_script_path, "solve", challenge_id]).strip()
p.sendline(solution)
p.recvuntil(b'[...] }\n')


path, e = [], []
for _ in range(30):
    for node in range(30):
        if node in path:
            continue
        path.append(node)
        payload = {"command": "check_path", "segment": path}
        p.sendline(json.dumps(payload))
        response = p.recvline().decode().strip()

        if 'path_complete' in response:
            e = json.loads(response)['lwe_error_magnitudes']
            break

        if 'valid_prefix' in response:
            break
        else:
            path.pop()

n, m, q = 50, 100, 1009
def Babai_closest_vector(M, G, target):
    small = target
    for _ in range(1):
        for i in reversed(range(M.nrows())):
            c = ((small * G[i]) / (G[i] * G[i])).round()
            small -= M[i] * c
    return target - small


with open("/home/team/CodePy/GoogleCTF2025/crypto-filtermaze/lwe_pub_params.json", "r") as f:
    data = json.load(f)
    A = Matrix(GF(q), m, n, data["A"])
    b = list(vector(GF(q), data["b"]))

e = vector(GF(q), e)
M = Matrix(ZZ, m + n, m)
for i in range(m):
    M[i, i] = q
    b[i] = b[i] / e[i]
for x in range(m):
    for y in range(n):
        A[x, y] = A[x, y] / e[x]
        M[m + y, x] = int(A[x, y])

lattice = IntegerLattice(M, lll_reduce=True)
gram = lattice.reduced_basis.gram_schmidt()[0]
target = vector(ZZ, b)
res = Babai_closest_vector(lattice.reduced_basis, gram, target)
s = A.solve_right(vector(GF(q), res))

p.sendline(json.dumps({"command": "get_flag", "lwe_secret_s": [int(x) for x in s]}))
flag = p.recvline().decode().strip()
print(flag)

os.remove(pow_script_path)

# CTF{d4_sup3r_sh0rt_3rr0r_v3ct0r_1s_th3_k3y}