#!/usr/bin/env python3
import argparse, hashlib, json, time, random, requests
from binascii import unhexlify, hexlify

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def modinv(a, n=N): return pow(a % n, -1, n)
def hx(b): return hexlify(b).decode()

def bip340_challenge(R_hex, PK_hex, m_bytes):
    Rx = unhexlify(R_hex)[1:33]
    Px = unhexlify(PK_hex)[1:33]
    tag = b"BIP0340/challenge"
    th = hashlib.sha256(tag).digest()
    h = hashlib.sha256(th + th + Rx + Px + m_bytes).digest()
    return int.from_bytes(h, 'big') % N

def beta_from_session(session_id, joint_pk_hex):
    h = hashlib.sha256()
    h.update(b"R_blind")
    h.update(session_id.encode())
    h.update(unhexlify(joint_pk_hex))
    return int.from_bytes(h.digest(), 'big') % N

def post(base, path, payload):
    r = requests.post(base + path, json=payload, timeout=10)
    r.raise_for_status()
    return r.json()

def ask_signature(base, msg_hex, client_id):
    while True:
        res = post(base, "/approvals/request", {"message": msg_hex, "client_id": client_id})
        if res.get("status") == "success":
            data = res["data"]
            sig = data["signature"]
            return {
                "session_id": data["session_id"],
                "R": sig["R"],
                "s_hex": sig["s"],
                "s_int": int(sig["s"], 16),
                "subset": sig["subset"],
            }
        err = res.get("error", {})
        if err.get("code") == "RATE_LIMIT_EXCEEDED":
            retry = int(err.get("details", {}).get("retry_after", 60))
            time.sleep(retry + 1)
            continue
        raise RuntimeError(f"Bad sign response: {res}")

def verify_and_get_pk(base, msg_hex, R_hex, s_hex):
    res = post(base, "/approvals/verify", {"message": msg_hex, "R": R_hex, "s": s_hex})
    if res.get("status") != "success" or "data" not in res:
        raise RuntimeError(f"Bad verify response: {res}")
    data = res["data"]
    if not data.get("valid", False):
        raise RuntimeError("Server says signature invalid (unexpected).")
    pk = data.get("joint_pubkey")
    if not pk:
        raise RuntimeError("No joint_pubkey returned.")
    return pk

def gauss_solve_mod(A, b, mod=N):
    m, n = len(A), len(A[0])
    aug = [ (A[i][:] + [b[i] % mod]) for i in range(m) ]
    row = 0
    piv_cols = []
    for col in range(n):
        sel = None
        for r in range(row, m):
            if aug[r][col] % mod != 0:
                sel = r; break
        if sel is None:
            continue
        aug[row], aug[sel] = aug[sel], aug[row]
        inv = modinv(aug[row][col], mod)
        for j in range(col, n+1):
            aug[row][j] = (aug[row][j] * inv) % mod
        for r in range(m):
            if r != row and aug[r][col] % mod != 0:
                f = aug[r][col] % mod
                for j in range(col, n+1):
                    aug[r][j] = (aug[r][j] - f * aug[row][j]) % mod
        piv_cols.append(col)
        row += 1
        if row == n: break
    if row < n:
        raise RuntimeError("Rank(A) < variables; need more diverse subsets.")
    x = [0]*n
    for i, c in enumerate(piv_cols):
        x[c] = aug[i][n] % mod
    return x

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="crypto2.cscv.vn")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--client-id", default="h4x0r")
    args = ap.parse_args()
    base = f"http://{args.host}:{args.port}"

    m = b"meet_frost_session_opt_bug"
    m_hex = hx(m)

    need_eq = 12
    rows = []
    subsets_seen = set()
    t0 = time.time()

    while len(rows) < need_eq:
        cur = ask_signature(base, m_hex, args.client_id)
        subset = tuple(cur["subset"])
        if subset in subsets_seen:
            time.sleep(7.0)
            if time.time() - t0 > 85:
                rows, subsets_seen, t0 = [], set(), time.time()
            continue
        subsets_seen.add(subset)
        rows.append(cur)
        print(f"    {len(rows):02d}: session={cur['session_id'][:8]} subset={subset} R[:6]={cur['R'][:6]} s[:10]={cur['s_hex'][:10]}")
        time.sleep(7.0)
        if time.time() - t0 > 85 and len(rows) < 10:
            rows, subsets_seen, t0 = [], set(), time.time()

    joint_pk = verify_and_get_pk(base, m_hex, rows[0]["R"], rows[0]["s_hex"])

    A, b = [], []
    sbase_list = []
    for r in rows:
        beta = beta_from_session(r["session_id"], joint_pk)
        c = bip340_challenge(r["R"], joint_pk, m)
        s_base = (r["s_int"] - beta) % N
        vec = [0]*9
        for i in r["subset"]:
            vec[i-1] = 1
        A.append(vec + [c])
        b.append(s_base)
        sbase_list.append((s_base, c))

    sol = gauss_solve_mod(A, b, N)
    k = sol[:9]
    x = sol[9]

    s_base1, c1 = sbase_list[0]
    r_base1 = (s_base1 - c1 * x) % N

    flag_m = b"RELEASE_THE_FLAG"
    c_star = bip340_challenge(rows[0]["R"], joint_pk, flag_m)
    s_base_star = (r_base1 + c_star * x) % N
    beta1 = beta_from_session(rows[0]["session_id"], joint_pk)
    s_pub_star = (s_base_star + beta1) % N
    s_star_hex = hex(s_pub_star)

    res = post(base, "/approvals/verify", {
        "message": hx(flag_m),
        "R": rows[0]["R"],
        "s": s_star_hex
    })
    data = res.get("data", {})
    token = data.get("authorization_token")
    if token:
        print(f"\nFLAG = {token}\n")

if __name__ == "__main__":
    main()
