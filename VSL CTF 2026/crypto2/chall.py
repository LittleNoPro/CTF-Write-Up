# import base64 as _b
# import zlib as _z
# _c = (
#     "eJxdkc1qwzAQhO9+CiEoSPlR4tCWEqoeUkhOgV56DrazSURlSUjrRu7T12qKHTwn7c6nWVY6eVuTd"
#     "986tOITlRamqUvwRNXOeiRlixAOaA/amjMpAtnMzoAfXtWQql32z9UFXlJjn22ldWAYPeniLDAi5c"
#     "JDcWQ8u16UBpKvM9IJfXs7JAWpDDJlXIOMBvUD5I1QTngPqBMJr1J3uVs+eVwON5Oc3LEwsKBvdL7"
#     "sNCZXT899p5Fu4voqyu2UFnTC8uleVKA0C4sXzu/8DYsCTGWPwO77cxkfhphWOntlcbaMaX4+awbS"
#     "+bRlWqJUhsXFwnE+X4393hOVbbqa5pSPmXYcD7ECh+sRRpX5LrQ6kr+XpUNK2f3IV/YLUzGDJA=="
# )

# print(_z.decompress(_b.b64decode(_c)).decode())
# exec(_z.decompress(_b.b64decode(_c)).decode())


from Crypto.Util.number import *
import math as M
F = open("flag.txt").read()
while 1:
    try:
        s = int(input("size > ") )
        if s <= len(F) * 40:
            p = getPrime(s)
        elif s <= 10000:
            p = 256
        u = p * p
        x = F + "a" * (1 + M.ceil(s/8))
        x = bytes_to_long(x.encode())
        x -= x % p
        y = pow(x, 0x10001, u)
        print(len(bin(x//p))-2)
        print(bin(x//p).count("1"))
        print(y,0x10001,u)
    except:
        print("invalid input")
        break