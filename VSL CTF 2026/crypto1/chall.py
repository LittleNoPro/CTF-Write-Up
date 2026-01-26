import hashlib
import os
import posixpath
import secrets
import time
import random
from typing import List
from flask import Flask, abort, jsonify, request

app = Flask(__name__)

Q = int("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
MAX_DEPTH = 4

FLAG = os.environ.get("FLAG")
TOKEN_SALT = os.environ.get("TOKEN_SALT", secrets.token_hex(16))
NONCE_WINDOW = int(os.environ.get(
    "NONCE_WINDOW", str(random.randint(100, 999))))

MSK = secrets.randbelow(Q)
DEPTH_NOISE: List[int] = [secrets.randbelow(2**32) for _ in range(MAX_DEPTH)]


def prime_mix(component: str, depth: int) -> int:
    base = hashlib.sha256(f"{depth}:{component}".encode()).digest()
    state = int.from_bytes(base, "big") % Q
    for round_idx in range(3):
        state = pow((state + 7 * (round_idx + 1)) % Q, 5, Q)
        state = (state * 3 + 11 * depth + round_idx) % Q
    return state


def derive_secret(identity: str) -> int:
    parts = [p for p in identity.split("/") if p]
    sk = MSK
    for depth, part in enumerate(parts, start=1):
        alpha = prime_mix(part, depth)
        noise_base = DEPTH_NOISE[min(depth - 1, len(DEPTH_NOISE) - 1)]
        noise = (noise_base * alpha + depth + 7) % Q
        sk = (alpha * sk + noise) % Q
    return sk


def stream_xor(key_int: int, data: bytes) -> bytes:
    key_bytes = hashlib.sha256(str(key_int).encode()).digest()
    keystream = bytearray()
    counter = 0
    while len(keystream) < len(data):
        block = hashlib.sha256(key_bytes + counter.to_bytes(4, "big")).digest()
        keystream.extend(block)
        counter += 1
    return bytes([d ^ k for d, k in zip(data, keystream)])


def encrypt(identity: str, plaintext: str) -> str:
    secret = derive_secret(identity)
    ct = stream_xor(secret, plaintext.encode())
    return ct.hex()


FLAG_IDENTITY = "admin/root"
FLAG_CIPHERTEXT = encrypt(FLAG_IDENTITY, FLAG)


def current_nonce() -> str:
    window = int(time.time() // NONCE_WINDOW)
    return hashlib.sha256(f"{TOKEN_SALT}:{window}".encode()).hexdigest()


@app.get("/")
def index():
    return """
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <title>Prime Vault</title>
      <style>
        :root {
          --bg: linear-gradient(135deg, #0f172a 0%, #111827 45%, #1f2937 100%);
          --card: rgba(255, 255, 255, 0.05);
          --accent: #22d3ee;
          --text: #e5e7eb;
          --muted: #94a3b8;
          --border: rgba(255, 255, 255, 0.08);
          --radius: 16px;
        }
        * { box-sizing: border-box; }
        body {
          margin: 0;
          min-height: 100vh;
          font-family: "Space Grotesk", "Segoe UI", sans-serif;
          background: var(--bg);
          color: var(--text);
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 32px;
        }
        .shell {
          width: min(1100px, 100%);
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
          gap: 18px;
        }
        .hero {
          grid-column: 1 / -1;
          background: var(--card);
          border: 1px solid var(--border);
          border-radius: var(--radius);
          padding: 28px;
          backdrop-filter: blur(12px);
          box-shadow: 0 20px 60px rgba(0,0,0,0.35);
        }
        h1 {
          margin: 0 0 8px;
          font-size: 28px;
          letter-spacing: -0.5px;
        }
        p {
          margin: 0 0 10px;
          color: var(--muted);
          line-height: 1.6;
        }
        .card {
          background: var(--card);
          border: 1px solid var(--border);
          border-radius: var(--radius);
          padding: 22px;
          backdrop-filter: blur(8px);
          box-shadow: 0 14px 40px rgba(0,0,0,0.32);
        }
        label {
          display: block;
          color: var(--muted);
          font-size: 14px;
          margin-bottom: 6px;
        }
        input {
          width: 100%;
          padding: 12px 14px;
          border-radius: 10px;
          border: 1px solid var(--border);
          background: rgba(255,255,255,0.03);
          color: var(--text);
          outline: none;
          transition: border-color 0.2s ease;
        }
        input:focus {
          border-color: var(--accent);
        }
        button {
          margin-top: 12px;
          padding: 12px 14px;
          border: none;
          border-radius: 12px;
          background: linear-gradient(120deg, #22d3ee, #14b8a6);
          color: #0b1224;
          font-weight: 700;
          cursor: pointer;
          width: 100%;
          box-shadow: 0 10px 30px rgba(20, 184, 166, 0.35);
        }
        button:hover { opacity: 0.95; }
        pre {
          background: rgba(0,0,0,0.35);
          border: 1px solid var(--border);
          padding: 12px;
          border-radius: 12px;
          color: #cbd5e1;
          overflow-x: auto;
          font-size: 13px;
        }
        .badge {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 8px 10px;
          background: rgba(34,211,238,0.12);
          border-radius: 10px;
          color: #22d3ee;
          border: 1px solid rgba(34,211,238,0.25);
          font-weight: 600;
        }
      </style>
    </head>
    <body>
      <div class="shell">
        <div class="hero">
          <div class="badge">Field Lab</div>
          <h1>Prime Vault</h1>
          <p>Minimal hierarchical encryption playground using a lightweight mix over a large prime field.</p>
          <p>Use the panels below to derive keys for identities and view the ciphertext stored on the vault.</p>
        </div>

        <div class="card">
          <h2>Derive Identity Key</h2>
          <label for="identity">Identity path</label>
          <input id="identity" placeholder="guest/demo" value="guest/demo" />
          <button onclick="fetchKey()">Request Key</button>
          <pre id="keyResult">Response will appear here.</pre>
        </div>

        <div class="card">
          <h2>View Ciphertext</h2>
          <p>Retrieve the protected ciphertext and target identity.</p>
          <button onclick="fetchCipher()">Fetch Ciphertext</button>
          <pre id="cipherResult">Response will appear here.</pre>
        </div>
      </div>

      <script>
        let vaultNonce = null;

        async function fetchNonce() {
          const res = await fetch("/api/nonce");
          const body = await res.json();
          vaultNonce = body.nonce;
          return vaultNonce;
        }

        async function authToken(identity, nonce) {
          const enc = new TextEncoder();
          const msg = enc.encode(identity + "|" + nonce);
          const buf = await crypto.subtle.digest("SHA-256", msg);
          const hex = Array.from(new Uint8Array(buf))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
          return hex.slice(0, 12);
        }

        async function fetchKey() {
          const nonce = vaultNonce || (await fetchNonce());
          const id = document.getElementById("identity").value.trim();
          const out = document.getElementById("keyResult");
          if (!id) {
            out.textContent = "Provide an identity path.";
            return;
          }
          try {
            const token = await authToken(id, nonce);
            const res = await fetch(
              `/api/key?identity=${encodeURIComponent(id)}&nonce=${nonce}`,
              { headers: { "X-Auth": token } }
            );
            const body = await res.json();
            if (!res.ok) {
              out.textContent = body.message || JSON.stringify(body, null, 2);
            } else {
              out.textContent = JSON.stringify(body, null, 2);
            }
          } catch (err) {
            out.textContent = err.toString();
          }
        }

        async function fetchCipher() {
          const out = document.getElementById("cipherResult");
          try {
            const res = await fetch("/api/ciphertext");
            const body = await res.json();
            if (!res.ok) {
              out.textContent = body.message || JSON.stringify(body, null, 2);
            } else {
              out.textContent = JSON.stringify(body, null, 2);
            }
          } catch (err) {
            out.textContent = err.toString();
          }
        }
      </script>
    </body>
    </html>
    """


def normalize_identity(raw_identity: str) -> str:
    normed = posixpath.normpath(raw_identity)
    return normed.replace("\\", "/")


@app.get("/api/key")
def api_key():
    raw_identity = request.args.get("identity", "").strip()
    if not raw_identity:
        abort(400, "missing identity")
    if not raw_identity.startswith("guest/"):
        abort(403, "access denied")

    client_nonce = request.args.get("nonce", "")
    if not client_nonce or client_nonce != current_nonce():
        abort(401, "invalid nonce")

    identity = normalize_identity(raw_identity)

    parts = [p for p in identity.split("/") if p]
    if len(parts) > MAX_DEPTH:
        abort(400, "invalid identity")

    if identity == FLAG_IDENTITY:
        abort(403, "access denied")

    expected_auth = hashlib.sha256(
        f"{identity}|{client_nonce}".encode()).hexdigest()[:12]
    provided_auth = request.headers.get("X-Auth", "")
    if provided_auth != expected_auth:
        abort(401, "auth failed")

    secret = derive_secret(identity)
    return jsonify(
        {
            "identity": identity,
            "secret_hex": hex(secret),
        }
    )


@app.get("/api/ciphertext")
def api_ciphertext():
    return jsonify(
        {
            "identity": FLAG_IDENTITY,
            "ciphertext_hex": FLAG_CIPHERTEXT,
        }
    )


@app.get("/api/nonce")
def api_nonce():
    return jsonify({"nonce": current_nonce(), "window": NONCE_WINDOW})


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(401)
def handle_errors(err):
    message = getattr(err, "description", "error")
    return jsonify({"message": message}), err.code


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9411)