from Crypto.Util.number import *
from sage.all import *
import os
import itertools

# --- 1. SETUP (Generate N=pqr) ---
p = getPrime(1024)
q = getPrime(1024)
r = getPrime(1024)
print(f"p = {p}")
print(f"q = {q}")
print(f"r = {r}")

N = p * q * r
e = 65537
d = pow(e, -1, (p - 1) * (q - 1) * (r - 1))
print(f"N = {N}")

# Chúng ta cần số mẫu > số ẩn (3). Chọn 6.
NUM_SAMPLES = 10
MSG = [os.urandom(32) for _ in range(NUM_SAMPLES)]

# --- 2. FAULT INJECTION SIMULATION ---
N_fault = []
N_bytes = long_to_bytes(N)
# Tạo lỗi ở byte cao nhất (MSB)
for i in range(NUM_SAMPLES):
    # Thay đổi giá trị byte đầu tiên để tạo N' khác N
    fault_val = (N_bytes[0] + i + 10) % 256
    if fault_val == N_bytes[0]: fault_val += 1

    nf_bytes = bytes([fault_val]) + N_bytes[1:]
    N_fault.append(bytes_to_long(nf_bytes))

# --- 3. SIGNATURE & CRT RECOVERY ---
sig_1 = [] # Correct sigs
sig_2 = [] # Faulty sigs

# Precompute CRT coeffs
Z = N
alpha_p = (Z // p) * inverse_mod(Z // p, p)
alpha_q = (Z // q) * inverse_mod(Z // q, q)
alpha_r = (Z // r) * inverse_mod(Z // r, r)

for i in range(NUM_SAMPLES):
    msg = bytes_to_long(MSG[i])
    sp = pow(msg, d, p)
    sq = pow(msg, d, q)
    sr = pow(msg, d, r)

    # Full CRT signature
    full_sig = (sp * alpha_p + sq * alpha_q + sr * alpha_r)

    sig_1.append(full_sig % N)
    sig_2.append(full_sig % N_fault[i])

# Recover v_i using CRT on (sig, sig')
v = []
for i in range(NUM_SAMPLES):
    # v[i] = sp*Ap + sq*Aq + sr*Ar (in Z, not mod N)
    val = crt([sig_1[i], sig_2[i]], [N, N_fault[i]])
    v.append(val)

print("-" * 20)
print("Attack phase started...")

# --- 4. LATTICE ATTACK ---

# Với N=pqr (3 primes), không gian ẩn có chiều là 3.
# Số vector trực giao cần tìm = NUM_SAMPLES - 3.
num_primes = 3
num_ortho = NUM_SAMPLES - num_primes

# === LATTICE 1: Find orthogonal vectors ===
# Trọng số K1 phải rất lớn để ép cột đầu tiên về 0
# Lớn hơn N để đảm bảo ưu tiên triệt tiêu tổng v[i]
K1 = 2 * N
dim1 = NUM_SAMPLES + 1
base1 = []

for i in range(NUM_SAMPLES):
    vec = [0] * dim1
    vec[0] = K1 * v[i]
    vec[i+1] = 1
    base1.append(vec)

M1 = Matrix(ZZ, base1)
print("Running LLL 1...")
reduced1 = M1.LLL()

# Lấy các vector trực giao từ reduced1
# Thay vì check row[0]==0, ta lấy num_ortho dòng ĐẦU TIÊN
# (Vì LLL sắp xếp vector ngắn nhất lên đầu, cột 0 chứa K1 lớn nên vector ngắn phải có cột 0 rất nhỏ/bằng 0)
ortho_vecs = []
for i in range(num_ortho):
    # Lấy row i, bỏ qua cột đầu tiên (trọng số)
    # reduced1[i] là vector (Weight*Sum, u1, u2, ..., u6)
    # Ta cần (u1, ..., u6)
    row = list(reduced1[i])
    ortho_vecs.append(row[1:])

print(f"Extracted {len(ortho_vecs)} orthogonal vectors.")

# === LATTICE 2: Recover Hidden Coefficients ===
# Xây dựng Lattice 2 từ các vector trực giao tìm được
K2 = 2**(1024 * 2) # Weight lớn cho phần Orthogonal
base2 = []

# Ma trận:
# [ K2 * ortho_vecs (dạng cột) | Identity ]
for i in range(NUM_SAMPLES):
    vec = []
    # Phần bên trái: Chiếu lên các vector trực giao
    for j in range(num_ortho):
        vec.append(K2 * ortho_vecs[j][i]) # ortho_vecs[j] là vector u^{(j)}

    # Phần bên phải: Ma trận đơn vị
    for j in range(NUM_SAMPLES):
        if i == j: vec.append(1)
        else: vec.append(0)
    base2.append(vec)

M2 = Matrix(ZZ, base2)
print("Running LLL 2...")
reduced2 = M2.LLL()

print(reduced2[2])
exit()

# --- 5. FACTORING ---
print("Attempting to factor...")

# reduced2 chứa các vector w xấp xỉ các thành phần đơn lẻ (sigma * alpha).
# Ta thử GCD(v[0] - w, N).
# Nếu w ~ sigma_p * alpha_p, thì v[0] - w ~ sigma_q*Aq + sigma_r*Ar.
# GCD(v[0] - w, N) sẽ trả về q*r (hoặc bội của nó).

found_factors = set()

# Lấy các giá trị w tương ứng với Sample 0 từ cơ sở đã giảm
# Cột tương ứng với Sample 0 là cột thứ `num_ortho`
w_candidates = []
rows_to_check = min(reduced2.nrows(), 10) # Kiểm tra 10 hàng đầu tiên
for r_idx in range(rows_to_check):
    val = reduced2[r_idx][num_ortho]
    w_candidates.append(val)

# Thử các tổ hợp tuyến tính nhỏ của w (để chính xác hơn)
# w = c1*w1 + c2*w2...
import itertools
coeffs = [-1, 0, 1] # Hệ số thử
combinations = list(itertools.product(coeffs, repeat=min(len(w_candidates), 3)))

for combo in combinations:
    if all(c==0 for c in combo): continue

    # Tạo w tổng hợp
    w_guess = sum(c*w for c, w in zip(combo, w_candidates[:3]))

    # Check GCD
    # Chúng ta thử cả cộng và trừ
    vals_to_check = [v[0] - w_guess, v[0] + w_guess]

    for val in vals_to_check:
        factor = gcd(val, N)
        if factor > 1 and factor < N:
            found_factors.add(factor)

# --- 6. CLEAN UP PRIMES ---
final_primes = set()

# Helper để tách số
def crack_composite(comp):
    # Nếu comp là tích 2 số (ví dụ q*r), làm sao tách?
    # Cách đơn giản nhất trong bài toán này:
    # Nếu ta tìm được q*r, thì p = N / (q*r).
    # Vậy ta có p. Có p rồi thì gcd(q*r, N) không giúp gì thêm.
    # Nhưng nếu ta tìm được 2 composite khác nhau: A = p*q, B = p*r.
    # Thì gcd(A, B) = p.
    pass

# Bước 1: Thu thập tất cả factors tìm được và cả phần bù của chúng
candidates = list(found_factors)
for f in found_factors:
    candidates.append(N // f)

# Bước 2: GCD chéo giữa các candidates để tách p, q, r
for i in range(len(candidates)):
    for j in range(i + 1, len(candidates)):
        g = gcd(candidates[i], candidates[j])
        if g > 1:
            if is_prime(g): final_primes.add(g)
            if is_prime(candidates[i] // g): final_primes.add(candidates[i] // g)
            if is_prime(candidates[j] // g): final_primes.add(candidates[j] // g)

# Bước 3: Kiểm tra trực tiếp các candidates xem có phải prime không
for f in candidates:
    if is_prime(f): final_primes.add(f)

# Bước 4: Kiểm tra xem đã đủ 3 chưa
if len(final_primes) < 3 and len(final_primes) > 0:
    # Nếu mới tìm được 1 prime (ví dụ p), tính rem = N // p = q*r
    # Ta cần tách q*r. Tuy nhiên thường GCD chéo ở trên đã giải quyết rồi.
    # Nếu chưa, ta in ra để người dùng biết.
    curr_primes = list(final_primes)
    rem = N
    for cp in curr_primes:
        rem //= cp
    if rem > 1 and is_prime(rem):
        final_primes.add(rem)

# IN KẾT QUẢ
sorted_primes = sorted(list(final_primes))
print("-" * 20)
if len(sorted_primes) == 3:
    print("SUCCESS! Recovered all 3 primes:")
    print("p =", sorted_primes[0])
    print("q =", sorted_primes[1])
    print("r =", sorted_primes[2])

    if sorted_primes[0] * sorted_primes[1] * sorted_primes[2] == N:
        print("\nVerification: MATCH N!")
else:
    print(f"Found {len(sorted_primes)} primes: {sorted_primes}")
    print("Raw factors found:", list(found_factors))