from Crypto.Util.number import getPrime, GCD, bytes_to_long, getRandomNBitInteger, long_to_bytes

while True:
    p = getPrime(1024)
    q = getPrime(1024)
    e = 0x101
    if GCD((p - 1) * (q - 1), e) == 1:
        break
N = p * q

flag = b'W1{??????????????????????????????}'

assert len(flag) == 34

flag = bytes_to_long(flag)
x = getRandomNBitInteger(flag.bit_length())
# x have 34 bytes

hint = x * flag
more_hint = long_to_bytes(hint) + long_to_bytes(x)

assert bytes_to_long(more_hint) == (hint << 8 * 34) + x

x_enc = pow(x, e, N)
hint_enc = pow(hint, e, N)
more_hint = pow(bytes_to_long(more_hint), e, N)

print(f"{N = }")
print(f"{e = }")
print(f"{x_enc = }")
print(f"{hint_enc = }")
print(f"{more_hint = }")