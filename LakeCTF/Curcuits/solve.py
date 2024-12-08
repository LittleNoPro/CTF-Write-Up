from pwn import *

r = remote("chall.polygl0ts.ch", 9068)

data = r.recvuntil(b"in ?")
r.sendline(b"3")

def process(type, num):
    data = r.recvuntil(b"test input")
    r.sendline(type.encode())

    if type == "2":
        data = r.recvuntil(b"input: ")
        r.sendline(num.encode())

        data = r.recvuntil(b"res = ")
        data = r.recvline()
        data = data[:len(data) - 1]

        return data.decode()

    else:
        data = r.recvuntil(b"bit: ")
        r.sendline(num.encode())
        print(f"b = {b}")

while True:
    data = r.recvline()
    data = data[:len(data) - 1]

    if data.decode() == "well done !!":
        break

    b = 0

    exits = [process("2", "0")]
    for i in range(1, 7):
        val = process("2", str(i))
        if val in exits:
            b = 1
            break
        exits.append(val)

    process("1", str(b))

print(r.recvline())


# Flag: EPFL{r4nd0m_c1rcu1t5_4r3_n0_g00d_rngs??}