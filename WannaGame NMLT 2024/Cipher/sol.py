from pwn import *

ROUND = 10
P = [12, 11, 8, 13, 5, 0, 6, 9, 15, 3, 1, 7, 10, 2, 4, 14]

def XOR(a, b):
    return list(set(a) ^ set(b))

def permute(block):
    new_block = []
    for i in range(16):
        new_block.append(block[P[i]])
    return new_block

def genroundkey(key):
    new_key = []
    for i in range(1, 16):
        new_key.append(key[i])

    last = []
    for i in [4, 2, 0, 6, 9, 14]:
        last = XOR(last, key[i])

    new_key.append(list(last))
    return new_key

# Initialization block and key
block, key = [], []
for i in range(16):
    block.append([])
    key.append([i])

# Encryption
for _ in range(ROUND):
    block = permute(block)
    key = genroundkey(key)

    lst = []
    for i in range(16):
        lst.append(XOR(block[i], key[i]))
    block = list(lst)

# Initialization matrix
matrix = []
for i in range(16):
    matrix.append([])
    for j in range(32):
        matrix[-1].append(-1)
for i in range(16):
    for j in block[i]:
        matrix[i][j] = j
    matrix[i][i + 16] = i + 16


# Khử gauss ma trận
def gauss_elimination():
    for col in range(16):
        p = -1
        for row in range(col, 16):
            if matrix[row][col] != -1:
                p = row
                break

        matrix[col], matrix[p] = matrix[p], matrix[col]
        for i in range(col + 1, 16):
            if matrix[i][col] != -1:
                for j in range(32):
                    if matrix[col][j] == matrix[i][j]:
                        matrix[i][j] = -1
                    else:
                        matrix[i][j] = j

# Đưa ma trận về ma trận đơn vị
def convert_to_unit():
    for col in range(15, -1, -1):
        for i in range(col - 1, -1, -1):
            if matrix[i][col] != -1:
                for j in range(col, 32):
                    if matrix[col][j] == matrix[i][j]:
                        matrix[i][j] = -1
                    else:
                        matrix[i][j] = j

gauss_elimination()
convert_to_unit()


conn = remote("chall.w1playground.com", 12919, level = 'DEBUG')
conn.sendlineafter(b"> ", b"0")
conn.sendlineafter(b"Enter your plaintext in hex: ", (b"\x00" * 16).hex())
ciphertext = conn.recvline().decode()
ciphertext = bytes.fromhex(ciphertext)[:16]

KEY = b""
for i in range(16):
    cur = b"\x00"
    for j in range(16, 32):
        if matrix[i][j] != -1:
            cur = xor(cur, ciphertext[j - 16])

    KEY += cur

conn.sendlineafter(b"> ", b"1")
conn.sendlineafter(b"Enter your guess: ", KEY.hex())
flag = conn.recvline()
print(flag.decode())

