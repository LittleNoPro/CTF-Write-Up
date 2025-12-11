from pwn import *
from hashlib import sha256
import base64
from Crypto.Util.number import *
from sage.all import *
import os
import itertools

while True:
    io = remote('challenge.cnsc.com.vn', 30289, level='debug')
    io.recvuntil(b"N = ")
    N_bytes = base64.a85decode(io.recvline().strip())
    N = bytes_to_long(N_bytes)

    def sign(payload):
        io.sendlineafter(b"Sign(0) or Verify(1): ", b"0")
        io.sendlineafter(b"base85:\n", payload)
        sig = io.recvline().strip().decode().split(' = ')[1]
        return bytes_to_long(base64.a85decode(sig))

    sig_1, sig_2, N_fault = [], [], []
    NUM_SAMPLES = 9
    MSG = [b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')']

    for b in range(NUM_SAMPLES):
        payload = MSG[b] * 79 + bytes([N_bytes[0]])
        sig_1.append(sign(payload))

    for b in range(NUM_SAMPLES):
        payload = MSG[b] * 79 + bytes([b + 1])
        sig_2.append(sign(payload))

        N_fault.append(bytes([b + 1]) + N_bytes[1:])
    N_fault = [bytes_to_long(nf) for nf in N_fault]

    v = []
    for i in range(NUM_SAMPLES):
        val = crt([sig_1[i], sig_2[i]], [N, N_fault[i]])
        v.append(val)

    num_primes = 3
    num_ortho = NUM_SAMPLES - num_primes

    K1 = 2 * N
    dim1 = NUM_SAMPLES + 1
    base1 = []

    for i in range(NUM_SAMPLES):
        vec = [0] * dim1
        vec[0] = K1 * v[i]
        vec[i + 1] = 1
        base1.append(vec)

    M1 = Matrix(ZZ, base1)
    print("Running LLL 1...")
    reduced1 = M1.LLL()

    ortho_vecs = []
    for i in range(num_ortho):
        row = list(reduced1[i])
        ortho_vecs.append(row[1:])

    K2 = 2**(1024 * 2)
    base2 = []

    for i in range(NUM_SAMPLES):
        vec = []
        for j in range(num_ortho):
            vec.append(K2 * ortho_vecs[j][i])

        for j in range(NUM_SAMPLES):
            if i == j: vec.append(1)
            else: vec.append(0)
        base2.append(vec)

    M2 = Matrix(ZZ, base2)
    print("Running LLL 2...")
    reduced2 = M2.LLL()

    print(reduced2[0])
    exit()

    found_factors = set()

    w_candidates = []
    rows_to_check = min(reduced2.nrows(), 10)
    for r_idx in range(rows_to_check):
        val = reduced2[r_idx][num_ortho]
        w_candidates.append(val)

    import itertools
    coeffs = [-1, 0, 1]
    combinations = list(itertools.product(coeffs, repeat=min(len(w_candidates), 3)))

    for combo in combinations:
        if all(c==0 for c in combo): continue

        w_guess = sum(c*w for c, w in zip(combo, w_candidates[:3]))

        vals_to_check = [v[0] - w_guess, v[0] + w_guess]

        for val in vals_to_check:
            factor = gcd(val, N)
            if factor > 1 and factor < N:
                found_factors.add(factor)

    final_primes = set()

    candidates = list(found_factors)
    for f in found_factors:
        candidates.append(N // f)

    for i in range(len(candidates)):
        for j in range(i + 1, len(candidates)):
            g = gcd(candidates[i], candidates[j])
            if g > 1:
                if is_prime(g): final_primes.add(g)
                if is_prime(candidates[i] // g): final_primes.add(candidates[i] // g)
                if is_prime(candidates[j] // g): final_primes.add(candidates[j] // g)

    for f in candidates:
        if is_prime(f): final_primes.add(f)

    sorted_primes = sorted(list(final_primes))
    if len(sorted_primes) == 3:
        p = sorted_primes[0]
        q = sorted_primes[1]
        r = sorted_primes[2]

        print(f"p = {p}")
        print(f"q = {q}")
        print(f"r = {r}")

        if p * q * r == N:
            print("Recover Success !!!")

        phi = (p - 1) * (q - 1) * (r - 1)
        e = 0x10001
        d = inverse(e, phi)

        target = b"1_d4r3_y0u_70_519n_7h15_3x4c7_51x7y_f0ur_by73_57r1n9_w17h_my_k3y"
        target = bytes_to_long(sha256(target).digest())
        sig = pow(target, d, N)

        sig_bytes = long_to_bytes(sig)
        if len(sig_bytes) < 384:
            sig_bytes = b'\x00' * (384 - len(sig_bytes)) + sig_bytes
        sig_payload = base64.a85encode(sig_bytes)

        io.sendlineafter(b"Sign(0) or Verify(1): ", b"1")
        io.sendlineafter(b"base85:\n", sig_payload)

        io.recvline()

        exit()

    io.close()

# W1{M@Y63_1-AM_NOt-@_G0oD-D3veIopeR...cf716}