from pwn import *
import string
import sys
import forbidden_attack

REQUEST_COUNT = 0

def get_size(io, payload):
    global REQUEST_COUNT
    try:
        io.sendline(b"0")

        io.sendlineafter(b"Plaintext:\n> ", payload.hex().encode())

        nonce = os.urandom(16)
        io.sendlineafter(b"Nonce:\n> ", nonce.hex().encode())

        REQUEST_COUNT += 1

        io.recvuntil(b"Storage left: ")
        line = io.recvline().decode().strip()
        raw_size = int(line.split('/')[0])

        compressed_size = raw_size - (REQUEST_COUNT * 16)

        io.recvuntil(b"Choose action:\n> ")

        return compressed_size
    except:
        return 999999

def leak_secret(io, prefix):
    known = prefix
    charset = string.ascii_letters + string.digits + "+/="

    global REQUEST_COUNT

    while True:
        candidates = {}

        payloads = []
        for char in charset:
            probe = (known + char).encode()
            payloads.append((char, probe))

        for char, probe in payloads:
            io.sendline(b"0")
            io.sendline(probe.hex().encode())
            nonce = os.urandom(16)
            io.sendline(nonce.hex().encode())

        for i, (char, probe) in enumerate(payloads):
            try:
                REQUEST_COUNT += 1

                io.recvuntil(b"Storage left: ")
                line = io.recvline().decode().strip()
                raw_size = int(line.split('/')[0])

                compressed_size = raw_size - (REQUEST_COUNT * 16)

                io.recvuntil(b"Choose action:\n> ")

                candidates[char] = compressed_size
            except:
                return known[len(prefix):]

        min_size = min(candidates.values())
        best_chars = [c for c, s in candidates.items() if s == min_size]

        if len(best_chars) == 1:
            best_char = best_chars[0]
            known += best_char

            if best_char == "\n" or len(known) > 100:
                break

            if best_char == "=":
                pass

            if len(known) - len(prefix) >= 24:
                break
        else:
            break

    return known[len(prefix):]

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def main():
    io = remote("challs.glacierctf.com", 13373, level='debug')

    io.recvuntil(b"Choose action:\n> ")

    try:
        nonce_b64 = leak_secret(io, "[+] Nonce: ")
        tag_b64 = leak_secret(io, "[+] Tag: ")

        nonce_admin = base64.b64decode(nonce_b64.strip())
        tag_admin = base64.b64decode(tag_b64.strip())

        P_admin = b"Hello GlacierCTF"

        io.sendline(b"0")

        P_ours = b"A" * 16
        io.sendlineafter(b"Plaintext:\n> ", P_ours.hex().encode())

        io.sendlineafter(b"Nonce:\n> ", nonce_admin.hex().encode())

        global REQUEST_COUNT
        REQUEST_COUNT += 1

        line = io.recvline().decode().strip()

        import re
        m_ct = re.search(r"ct\.hex\(\)='([0-9a-f]+)'", line)
        m_tag = re.search(r"tag\.hex\(\)='([0-9a-f]+)'", line)

        C_ours_hex = m_ct.group(1)
        Tag_ours_hex = m_tag.group(1)

        C_ours = bytes.fromhex(C_ours_hex)
        Tag_ours = bytes.fromhex(Tag_ours_hex)

        io.recvuntil(b"Storage left: ")
        io.recvline()
        io.recvuntil(b"Choose action:\n> ")

        K = xor_bytes(C_ours, P_ours)

        C_admin = xor_bytes(P_admin, K)

        possible_keys = list(forbidden_attack.recover_possible_auth_keys(
            b"", C_admin, tag_admin,
            b"", C_ours, Tag_ours
        ))

        ADMIN_SECRET = b"Glacier CTF Open"
        P_flag_request = ADMIN_SECRET
        if len(P_flag_request) < 16:
            P_flag_request += b'\x00' * (16 - len(P_flag_request))

        C_flag_request = xor_bytes(P_flag_request, K)

        for i, H in enumerate(possible_keys):
            Tag_flag_request = forbidden_attack.forge_tag(
                H,
                b"", C_admin, tag_admin,
                b"", C_flag_request
            )

            io.sendline(b"1")
            io.sendlineafter(b"Ciphertext:\n> ", C_flag_request.hex().encode())
            io.sendlineafter(b"Nonce:\n> ", nonce_admin.hex().encode())
            io.sendlineafter(b"Tag:\n> ", Tag_flag_request.hex().encode())

            response = io.recvall(timeout=2).decode()
            return response
    except:
        return ""
    finally:
        io.close()

if __name__ == "__main__":
    print(main())
