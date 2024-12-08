from pwn import *

while True:
    hex_value = "91" # số nào cũng được thuộc đoạn [0..255]

    r = remote("chall.polygl0ts.ch", 9001)

    data = r.recvline()
    data = r.recvline()

    r.sendline(hex_value.encode())

    data = r.recvline()
    res = data[:len(data) - 1].decode()
    print(hex_value.encode(), res)

    if res == "it's valid":
        for i in range(3):
            data = r.recvline()
            r.sendline(hex_value.encode())
            data = r.recvline()
        flag = r.recvline()
        print(flag)

        exit()

    r.close()

# Flag: EPFL{wH4T_d0_yOu_m34n_4_W1LdC4Rd}