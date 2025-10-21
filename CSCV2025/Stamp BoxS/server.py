import asyncio
import hashlib
import os
import re
from typing import Dict, List

from secret import key_e, key_d, key_n, flag, admin_password

assert 1024 <= key_n.bit_length() <= 4096
assert 1 < key_e < 2**32

admin_name = "campus_admin_2025"
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{1,200}$")


def bytes_to_long(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")


def rsa_sign(username: str) -> int:
    m = bytes_to_long(username.encode("utf-8"))
    return pow(m, key_d, key_n)


def rsa_verify(username: str, sig: int) -> bool:
    m = bytes_to_long(username.encode("utf-8"))
    return m == pow(sig, key_e, key_n)


class InMemoryDB:
    def __init__(self) -> None:
        self.users: Dict[str, str] = {}
        self.entries: List[Dict[str, str]] = []
        self.lock = asyncio.Lock()

    async def add_user(self, name: str, password: str) -> None:
        async with self.lock:
            self.users[name] = password

    async def check_user(self, name: str, password: str) -> bool:
        async with self.lock:
            return self.users.get(name) == password

    async def add_entry(self, user_name: str, content: str, hidden: bool) -> None:
        async with self.lock:
            self.entries.append({
                "user_name": user_name,
                "content": content,
                "hidden": "true" if hidden else "false",
            })

    async def public_feed(self) -> List[Dict[str, str]]:
        async with self.lock:
            return [e for e in self.entries if e["hidden"] == "false"]


DB = InMemoryDB()


async def seed_data() -> None:
    await DB.add_user(admin_name, admin_password)
    await DB.add_entry(
        admin_name,
        (
            "Today’s tip: \"A stamp is m^d mod n. To check a stamp s, compute s^e; "
            "if it equals the original message m, it’s valid. Hashing and padding are "
            "complicated—we keep it simple!\" — Student IT"
        ),
        hidden=False,
    )
    await DB.add_entry(admin_name, flag, hidden=True)


WELCOME = (
    "Welcome to CampusID Stamp Box (demo)\n"
    "Type HELP for commands. Usernames must match ^[a-zA-Z0-9_]{1,200}$.\n"
    "This demo uses \"simple math stamps\" for compatibility.\n"
)


HELP_TEXT = (
    "Commands:\n"
    "  HELP\n"
    "  REGISTER <u> <p>      -> create or update your account\n"
    "  LOGIN <u> <p>         -> returns token 'u||signature' (signature decimal)\n"
    "  VERIFY <u> <sig>      -> verifies that pow(sig, e, n) == bytes_to_long(u)\n"
    "  FEED                  -> public notes\n"
    "  ADD <public|hidden> <content>  -> add entry (requires LOGIN in this session)\n"
    "  GETFLAG <token>       -> returns flag if token is valid and u == %s\n"
    % admin_name
)


async def pow_challenge(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
    zeros = int(os.environ.get("POW_ZEROS", "5"))
    if zeros <= 0:
        return True
    prefix = os.urandom(16)
    target = "0" * zeros
    async def writeln(s: str) -> None:
        writer.write((s + "\n").encode())
        await writer.drain()
    await writeln("PROOF-OF-WORK")
    await writeln(f"prefix={prefix.hex()}")
    await writeln(f"target_prefix={target}")
    await writeln("Reply with: NONCE <hex>")
    line = await reader.readline()
    if not line:
        return False
    s = line.decode(errors="ignore").strip()
    if not s.startswith("NONCE "):
        await writeln("Bad PoW format")
        return False
    hex_nonce = s.split(" ", 1)[1]
    try:
        nonce = bytes.fromhex(hex_nonce)
    except Exception:
        await writeln("Bad PoW nonce")
        return False
    h = hashlib.sha256(prefix + nonce).hexdigest()
    if not h.startswith(target):
        await writeln("Bad PoW solution")
        return False
    return True


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    addr = writer.get_extra_info("peername")
    logged_user = None
    last_token = None

    async def writeln(s: str) -> None:
        writer.write((s + "\n").encode())
        await writer.drain()

    # Proof-of-Work handshake (optional via POW_ZEROS)
    ok = await pow_challenge(reader, writer)
    if not ok:
        try:
            writer.close()
            await writer.wait_closed()
        finally:
            return
    await writeln(WELCOME.rstrip("\n"))
    while True:
        line = await reader.readline()
        if not line:
            break
        try:
            cmdline = line.decode().strip()
            if not cmdline:
                continue
            parts = cmdline.split(" ", 2)
            cmd = parts[0].upper()
            if cmd == "HELP":
                await writeln(HELP_TEXT)
            elif cmd == "REGISTER":
                if len(parts) < 3:
                    await writeln("Usage: REGISTER <username> <password>")
                    continue
                u, p = parts[1], parts[2]
                if u == admin_name:
                    await writeln("That username is reserved")
                    continue
                if not USERNAME_RE.match(u):
                    await writeln("Invalid username regex")
                    continue
                await DB.add_user(u, p)
                await writeln("OK")
            elif cmd == "LOGIN":
                if len(parts) < 3:
                    await writeln("Usage: LOGIN <username> <password>")
                    continue
                u, p = parts[1], parts[2]
                if not USERNAME_RE.match(u):
                    await writeln("Invalid username regex")
                    continue
                if not await DB.check_user(u, p):
                    await writeln("Invalid credentials")
                    continue
                s = rsa_sign(u)
                token = f"{u}||{s}"
                logged_user = u
                last_token = token
                await writeln(token)
            elif cmd == "VERIFY":
                if len(parts) < 3:
                    await writeln("Usage: VERIFY <username> <signature>")
                    continue
                u, sig_str = parts[1], parts[2]
                if not USERNAME_RE.match(u):
                    await writeln("Invalid username regex")
                    continue
                try:
                    sig = int(sig_str)
                except ValueError:
                    await writeln("Signature must be a decimal integer")
                    continue
                await writeln("OK" if rsa_verify(u, sig) else "FAIL")
            elif cmd == "FEED":
                feed = await DB.public_feed()
                if not feed:
                    await writeln("(no public notes)")
                else:
                    for e in feed:
                        await writeln(f"[{e['user_name']}] {e['content']}")
            elif cmd == "ADD":
                if len(parts) < 3:
                    await writeln("Usage: ADD <public|hidden> <content>")
                    continue
                if logged_user is None:
                    await writeln("Please LOGIN first in this session")
                    continue
                scope, content = parts[1], parts[2]
                if scope not in ("public", "hidden"):
                    await writeln("Scope must be 'public' or 'hidden'")
                    continue
                await DB.add_entry(logged_user, content, hidden=(scope == "hidden"))
                await writeln("OK")
            elif cmd == "GETFLAG":
                if len(parts) < 2:
                    await writeln("Usage: GETFLAG <token>")
                    continue
                token = parts[1]
                if "||" not in token:
                    await writeln("Bad token format")
                    continue
                u, sig_str = token.split("||", 1)
                if not USERNAME_RE.match(u):
                    await writeln("Invalid username regex")
                    continue
                try:
                    sig = int(sig_str)
                except ValueError:
                    await writeln("Bad token signature")
                    continue
                if rsa_verify(u, sig) and u == admin_name:
                    await writeln(flag)
                else:
                    await writeln("Access denied")
            else:
                await writeln("Unknown command. Type HELP.")
        except Exception as ex:
            await writeln(f"Error: {ex}")

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass


async def run_server() -> None:
    await seed_data()
    server = await asyncio.start_server(handle_client, "0.0.0.0", 31337)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    async with server:
        await server.serve_forever()


def main() -> None:
    asyncio.run(run_server())


if __name__ == "__main__":
    main()


