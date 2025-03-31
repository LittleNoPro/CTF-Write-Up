from pwn import *
from tqdm import tqdm
from Crypto.Util.Padding import pad

alphabet = string.ascii_letters+string.digits

io = remote("94.237.54.190", 40497, level = 'debug')

password = ""
length = 32 + 15
for _ in tqdm(range(20)):
    user = "0" * length

    io.sendafter(b"Choose your path, traveler :: ", b"1\n")
    io.sendafter(b'[+] Speak thy name, so it may be sealed in the archives :: ', user.encode() + b'\n')

    io.recvuntil(b"[+] Thy credentials have been sealed in the encrypted scrolls: ")
    target = io.recvline().decode()
    target = bytes.fromhex(target)

    for ch in alphabet:
        cur_user = user + password + ch
        io.sendafter(b"Choose your path, traveler :: ", b"1\n")
        io.sendafter(b'[+] Speak thy name, so it may be sealed in the archives :: ', cur_user.encode() + b'\n')

        io.recvuntil(b"[+] Thy credentials have been sealed in the encrypted scrolls: ")
        cur = io.recvline().decode()
        cur = bytes.fromhex(cur)

        if cur[16:48] == target[16:48]:
            password += ch
            print(password)
            length -= 1
            break



io.sendafter(b"Choose your path, traveler :: ", b"2\n")
io.sendafter(b"[+] Whisper the sacred incantation to enter the Forbidden Sanctum :: ", password.encode() + b'\n')
io.recvall()


# HTB{encrypting_with_CBC_decryption_is_as_insecure_as_ECB___they_also_both_fail_the_penguin_test_cf4d671608cad423ca312ad501b030b8}