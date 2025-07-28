from decimal import Decimal, getcontext
from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

getcontext().prec = 50

leak = 4336282047950153046404
ct = '7863c63a4bb2c782eb67f32928a1deceaee0259d096b192976615fba644558b2ef62e48740f7f28da587846a81697745'
ct = bytes.fromhex(ct)

leak_str = str(leak)
d = len(leak_str)

for int_part in range(10**5, 10**6):
    approx = Decimal(int_part) + Decimal(leak) / (10**d)
    K_approx = int((approx ** 2).to_integral_value())
    key = md5(str(K_approx).encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        pt = unpad(cipher.decrypt(ct), 16)
        if b"uiuctf" in pt:
            print(pt)
            break
    except:
        continue
