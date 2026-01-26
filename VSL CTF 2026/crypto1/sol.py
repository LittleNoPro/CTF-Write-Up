#!/usr/bin/env python3
"""
Remote solver for the Prime Vault challenge.

Key ideas
- The derived key at depth 1 is sk = alpha1 * (MSK + N0) + 8.
- At depth 2 it becomes sk = alpha1 * alpha2 * (MSK + N0) + 8 * alpha2 + alpha2 * N1 + 9.
- By querying identities we control, we can solve for K1 = (MSK + N0) and N1.
- The target secret for admin/root is then
    sk_flag = alpha_admin * alpha_root * K1 + alpha_root * N1 + 8 * alpha_root + 9.
"""

import hashlib
import os
import posixpath
import requests

Q = int("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
BASE_URL = os.environ.get("VAULT_URL", "http://124.197.22.141:6664")


def prime_mix(component: str, depth: int) -> int:
    base = hashlib.sha256(f"{depth}:{component}".encode()).digest()
    state = int.from_bytes(base, "big") % Q
    for round_idx in range(3):
        state = pow((state + 7 * (round_idx + 1)) % Q, 5, Q)
        state = (state * 3 + 11 * depth + round_idx) % Q
    return state


def stream_xor(key_int: int, data: bytes) -> bytes:
    key_bytes = hashlib.sha256(str(key_int).encode()).digest()
    keystream = bytearray()
    counter = 0
    while len(keystream) < len(data):
        block = hashlib.sha256(key_bytes + counter.to_bytes(4, "big")).digest()
        keystream.extend(block)
        counter += 1
    return bytes(d ^ k for d, k in zip(data, keystream))


def modinv(x: int) -> int:
    return pow(x, Q - 2, Q)


def fetch_nonce() -> str:
    return requests.get(f"{BASE_URL}/api/nonce", timeout=5).json()["nonce"]


def auth_token(identity_norm: str, nonce: str) -> str:
    return hashlib.sha256(f"{identity_norm}|{nonce}".encode()).hexdigest()[:12]


def fetch_secret(identity_raw: str, nonce: str) -> int:
    identity_norm = posixpath.normpath(identity_raw)
    token = auth_token(identity_norm, nonce)
    res = requests.get(
        f"{BASE_URL}/api/key",
        params={"identity": identity_raw, "nonce": nonce},
        headers={"X-Auth": token},
        timeout=5,
    )
    res.raise_for_status()
    return int(res.json()["secret_hex"], 16)


def fetch_ciphertext() -> bytes:
    res = requests.get(f"{BASE_URL}/api/ciphertext", timeout=5)
    res.raise_for_status()
    data = res.json()
    return bytes.fromhex(data["ciphertext_hex"])


def recover_parameters(nonce: str):
    """Recover K1 = MSK+N0 and N1 using two oracle queries."""
    alpha_guest = prime_mix("guest", 1)
    sk_guest = fetch_secret("guest/.", nonce)
    K1 = ((sk_guest - 8) * modinv(alpha_guest)) % Q

    alpha_a = prime_mix("a", 2)
    sk_guest_a = fetch_secret("guest/a", nonce)
    term = (sk_guest_a - alpha_guest * alpha_a * K1 - 8 * alpha_a - 9) % Q
    N1 = (term * modinv(alpha_a)) % Q
    return K1, N1


def derive_flag_secret(K1: int, N1: int) -> int:
    alpha_admin = prime_mix("admin", 1)
    alpha_root = prime_mix("root", 2)
    return (alpha_admin * alpha_root * K1 + alpha_root * N1 + 8 * alpha_root + 9) % Q


def main():
    print(f"[+] Target: {BASE_URL}")
    nonce = fetch_nonce()
    print(f"[+] Nonce: {nonce}")

    print("[+] Recovering linear parameters from oracle...")
    K1, N1 = recover_parameters(nonce)
    print(f"    K1 = MSK+N0 = {hex(K1)}")
    print(f"    N1         = {hex(N1)}")

    print("[+] Fetching ciphertext and deriving admin/root secret...")
    ct = fetch_ciphertext()
    secret_flag = derive_flag_secret(K1, N1)
    flag = stream_xor(secret_flag, ct).decode()

    print("\nFLAG:", flag)


if __name__ == "__main__":
    main()
