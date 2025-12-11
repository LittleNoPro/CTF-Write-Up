from sage.all import *
from pwn import *
from Crypto.Util.number import long_to_bytes

# =============================================================================
# 1. Local CO Class (Minimal)
# =============================================================================
class CO:
    def __init__(self, p, G, O):
        self.Fp = GF(p)
        self.G = [self.Fp(c) for c in G]
        self.O = [self.Fp(c) for c in O]
        # L random (needed for init, but not used in add)
        M = matrix(self.Fp, [self.G, self.O])
        self.L = self.random_element_from_basis(M.right_kernel_matrix())

    def random_element_from_basis(self, M):
        val = 0
        n = M.nrows()
        for i in range(n):
            val += self.Fp.random_element() * M[i]
        return val

    def intersect(self, P, Q):
        aa = P[0]-Q[0]; bb = P[1]-Q[1]; cc = P[2]-Q[2]; dd = P[3]-Q[3]
        A = aa*bb**2 + bb*cc**2 + cc*dd**2 + dd*aa**2
        C = (P[1]**2 + 2*P[0]*P[3])*aa + (P[2]**2 + 2*P[0]*P[1])*bb + \
            (P[3]**2 + 2*P[1]*P[2])*cc + (P[0]**2 + 2*P[2]*P[3])*dd

        if A == 0: return self.O
        t = -C / A
        return [P[0]+t*aa, P[1]+t*bb, P[2]+t*cc, P[3]+t*dd]

    def neg(self, P):
        if P == self.O: return P
        return self.intersect(P, self.O)

    def add(self, P, Q):
        if P == self.O: return Q
        if Q == self.O: return P
        R = self.intersect(P, Q)
        return self.neg(R)

# =============================================================================
# 2. Helpers
# =============================================================================
def generate_smooth_prime(target_bits=256):
    print("[*] Generating smooth prime...")
    while True:
        p_minus_1 = 1
        for q in primes(2, 4000):
            p_minus_1 *= q
            if p_minus_1.bit_length() >= target_bits - 20: break

        lower = (1 << (target_bits - 1)) // p_minus_1
        upper = (1 << target_bits) // p_minus_1

        for k in range(lower, upper + 1):
            p = k * p_minus_1 + 1
            if p.bit_length() == target_bits and is_prime(p) and p % 4 == 1:
                 return p

def find_valid_G(p, O):
    F = GF(p)
    # x*y^2 + y*z^2 + z*w^2 + w*x^2 = 0
    while True:
        x, y, z = F.random_element(), F.random_element(), F.random_element()
        if z == 0: continue
        # Solve for w (quadratic)
        A, B, C = z, x**2, x*y**2 + y*z**2
        delta = B**2 - 4*A*C
        if is_square(delta):
            w = (-B + sqrt(delta)) / (2*A)
            G = [x, y, z, w]
            if G != O: return [int(c) for c in G]

# =============================================================================
# 3. Hunter Logic
# =============================================================================
def hunt_map_and_twist(p, O):
    print("[*] Hunting for Isomorphism & Twist Constant...")
    F = GF(p)
    i_unit = F(-1).sqrt()

    # Generate Test Points
    # We need a few pairs to confirm consistency
    pairs = []
    for _ in range(3):
        G1 = find_valid_G(p, O)
        G2 = find_valid_G(p, O)
        while G1 == G2: G2 = find_valid_G(p, O)
        curve = CO(p, G1, O)
        G3 = curve.add([F(c) for c in G1], [F(c) for c in G2])
        if G3 == [F(c) for c in O]: continue # Skip identity results
        pairs.append( (G1, G2, G3) )

    if not pairs: return None, None

    # Define Candidate Maps (functions of coordinates)
    # We suspect (y - i*w)/(y + i*w) or similar

    def map_yw_i(pt):
        y, w = F(pt[1]), F(pt[3])
        return (y - i_unit*w) / (y + i_unit*w)

    def map_yw_i_inv(pt):
        y, w = F(pt[1]), F(pt[3])
        return (y + i_unit*w) / (y - i_unit*w)

    # Add more candidates if needed (e.g., x/z based)
    candidates = [
        (" (y-iw)/(y+iw) ", map_yw_i),
        (" (y+iw)/(y-iw) ", map_yw_i_inv),
    ]

    for name, func in candidates:
        try:
            # Check Twist: mu = phi(C) / (phi(A)*phi(B))
            # It must be CONSTANT for all pairs
            mu_candidates = []
            valid_candidate = True

            for A, B, C in pairs:
                vA = func(A)
                vB = func(B)
                vC = func(C)
                if vA*vB == 0:
                    valid_candidate = False; break

                mu = vC / (vA * vB)
                mu_candidates.append(mu)

            if not valid_candidate: continue

            # Check if all calculated mu are the same
            first_mu = mu_candidates[0]
            if all(m == first_mu for m in mu_candidates):
                print(f"[+] Found Consistent Map: {name}")
                print(f"[+] With Twist Constant mu: {first_mu}")
                return func, first_mu

        except Exception as e:
            continue

    print("[-] No consistent map found in candidates.")
    return None, None

# =============================================================================
# 4. Main Attack
# =============================================================================
HOST = "challenge.cnsc.com.vn"
PORT = 32166

# Setup
p = generate_smooth_prime()
print(f"[+] p = {p}")

O = [0, 1, 0, 0]

# Find Map & Twist
phi_func, mu = hunt_map_and_twist(p, O)
if phi_func is None:
    print("[-] Failed to find map locally. Exiting.")
    exit()

G = find_valid_G(p, O)

# Connect
r = remote(HOST, PORT)
r.sendlineafter(b"p = ", str(p).encode())
r.sendlineafter(b"G = ", ",".join(map(str, G)).encode())
r.sendlineafter(b"O = ", ",".join(map(str, O)).encode())

r.recvuntil(b"P = ")
P_list = sage_eval(r.recvline().strip().decode())
print(f"[+] Received P")

try:
    # Apply Map
    val_G = phi_func(G)
    val_P = phi_func(P_list)

    # Apply Twist Correction for DLP
    # Relation: phi(P) * mu = (phi(G) * mu)^flag
    # Reason: phi(A+B) = mu * phi(A) * phi(B)
    # => phi(kG) * mu = (phi(G) * mu)^k

    target = val_P * mu
    base = val_G * mu

    print("[*] Solving Discrete Log with Twist...")
    # Calculate order of base
    order = base.multiplicative_order()
    print(f"[*] Base Order: {order}")

    flag_int = discrete_log(target, base, ord=order)

    print(f"[+] Flag Int: {flag_int}")
    print(f"FLAG: W1{{{long_to_bytes(int(flag_int)).decode()}}}")

except Exception as e:
    print(f"[-] Attack failed: {e}")

r.close()