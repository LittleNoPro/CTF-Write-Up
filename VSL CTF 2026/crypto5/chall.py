import os
import signal
import socket
import sys
import string
import random
from Crypto.Cipher import ARC4

BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║                  🔐 RETRO CIPHER VAULT 🔐                     ║
║          Crack the ancient RC4 encryption to win!             ║
╚═══════════════════════════════════════════════════════════════╝
"""

ALLOWED_CHARS = string.digits + string.ascii_lowercase + string.ascii_uppercase
KEY_LENGTH = 16
MAX_QUERIES = 1000
DROP_BYTES = 3072


def generate_master_key():
    return "".join(random.choice(ALLOWED_CHARS) for _ in range(KEY_LENGTH)).encode()


def decrypt_message(master_key, iv, ciphertext):
    combined_key = master_key + iv
    cipher = ARC4.new(combined_key, drop=DROP_BYTES)
    return cipher.decrypt(ciphertext)


def encrypt_message(master_key, iv, plaintext):
    combined_key = master_key + iv
    cipher = ARC4.new(combined_key, drop=DROP_BYTES)
    return cipher.encrypt(plaintext)


def handle_vault_session(conn, addr):
    original_stdin = sys.stdin
    original_stdout = sys.stdout

    class SocketInput:
        def __init__(self, connection):
            self.connection = connection
            self.data_buffer = b""

        def readline(self):
            while b"\n" not in self.data_buffer:
                chunk = self.connection.recv(1024)
                if not chunk:
                    return ""
                self.data_buffer += chunk
            line, self.data_buffer = self.data_buffer.split(b"\n", 1)
            return line.decode()

    class SocketOutput:
        def __init__(self, connection):
            self.connection = connection

        def write(self, message):
            self.connection.sendall(
                message.encode() if isinstance(message, str) else message)

        def flush(self):
            pass

    sys.stdin = SocketInput(conn)
    sys.stdout = SocketOutput(conn)

    try:
        signal.alarm(300)

        secret_flag = os.environ.get("FLAG", "VSL{REDACTED}")

        master_key = generate_master_key()

        print(BANNER)
        print(f"🔑 A secret master key guards the vault...")
        print(f"📊 You have {MAX_QUERIES} decryption queries available.")
        print(f"🎯 Recover the master key to unlock the treasure!")
        print()

        for query_num in range(MAX_QUERIES):
            print(f"━━━ Query #{query_num + 1}/{MAX_QUERIES} ━━━")

            try:
                iv_hex = input("iv: ").strip()
                iv = bytes.fromhex(iv_hex)

                ciphertext_hex = input("ciphertext: ").strip()
                ciphertext = bytes.fromhex(ciphertext_hex)

                plaintext = decrypt_message(master_key, iv, ciphertext)

                if plaintext == master_key:
                    print()
                    print(
                        "╔═══════════════════════════════════════════════════════════════╗")
                    print(
                        "║           🎉 VAULT UNLOCKED! KEY RECOVERED! 🎉               ║")
                    print(
                        "╚═══════════════════════════════════════════════════════════════╝")
                    print(f"💎 Secret Treasure: {secret_flag}")
                    conn.close()
                    return

                print(f"plaintext: {plaintext.hex()}")
                print()

            except Exception as e:
                print(f"⚠️ Invalid input format. Use hex strings.")
                print()
                continue

        print()
        print("💀 Out of queries! The vault remains sealed forever...")
        print("Game Over!")

    except Exception as e:
        print(f"⚠️ An error occurred in the vault...")
    finally:
        sys.stdin = original_stdin
        sys.stdout = original_stdout
        conn.close()


if __name__ == "__main__":
    vault_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    vault_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    vault_server.bind(("0.0.0.0", 6668))
    vault_server.listen(5)
    print("🔐 Retro Cipher Vault listening on port 6668...")

    while True:
        client, client_addr = vault_server.accept()
        print(f"🔓 New vault access attempt from {client_addr}")
        handle_vault_session(client, client_addr)