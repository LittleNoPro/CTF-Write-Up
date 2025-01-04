from hashlib import sha256
from random import choices

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


pt = "4145535f4145535f4145535f41455321"
pt = bytes.fromhex(pt)
ct = "a5d45cdb322abe38b9da6df19f997696"
ct = bytes.fromhex(ct)
enc_flag = "ecd0486b5c1c5a2b9af4e42abc8891445a97337cf1857e366bff6063bdbeaa7f"
enc_flag = bytes.fromhex(enc_flag)

s = "AoThuatGiDP"
lst = []
for i in range(len(s)):
    for j in range(len(s)):
        for k in range(len(s)):
            lst.append(s[i] + s[j] + s[k])

dic = {}
for w in lst:
    for x in lst:
        k1 = sha256(w.encode()).digest()
        k2 = sha256(x.encode()).digest()

        _ct = AES.new(k2, AES.MODE_ECB).encrypt(
                AES.new(k1, AES.MODE_ECB).encrypt(
                    pt
                )
            )
        dic[_ct] = (w, x)

_w, _x, _y, _z = None, None, None, None
for y in lst:
    for z in lst:
        k3 = sha256(y.encode()).digest()
        k4 = sha256(z.encode()).digest()

        _pt = AES.new(k3, AES.MODE_ECB).decrypt(
                AES.new(k4, AES.MODE_ECB).decrypt(
                    ct
                )
            )

        if _pt in dic:
            _y, _z = y, z
            _w, _x = dic[_pt][0], dic[_pt][1]
            print(f"w = {_w}")
            print(f"x = {_x}")
            print(f"y = {_y}")
            print(f"z = {_z}")
            print("--------")
            break

_w, _x, _y, _z = _w.encode(), _x.encode(), _y.encode(), _z.encode()
key = sha256(_w + _x + _y + _z).digest()
flag = AES.new(key, AES.MODE_ECB).decrypt(enc_flag)
print(flag)

# Flag: W1{y0u_kn0w_m4n_1n_7h3_m1ddl3}