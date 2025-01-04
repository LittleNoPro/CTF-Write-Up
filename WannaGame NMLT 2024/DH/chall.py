from Crypto.Util.number import isPrime, long_to_bytes, getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from random import randint
from hashlib import sha256


FLAG = b"W1{fake-flag}"

class DH:

    def __init__(self):
        self.gen_params()

    def gen_params(self):
        self.r = getPrime(512)

        while True:
            self.q = getPrime(42)
            self.p = (2 * self.q * self.r) + 1
            if isPrime(self.p):
                break

        while True:
            self.h = getPrime(42)
            self.g = pow(self.h, 2 * self.r, self.p)
            if self.g != 1:
                break

        self.a = randint(2, self.p - 2)
        self.b = randint(2, self.p - 2)

        self.A, self.B = pow(self.g, self.a, self.p), pow(self.g, self.b, self.p)
        self.ss = pow(self.A, self.b, self.p)

    def encrypt(self, flag_part):
        key = sha256(long_to_bytes(self.ss)).digest()[:16]
        cipher = AES.new(key, AES.MODE_ECB)
        ct = cipher.encrypt(pad(flag_part, 16)).hex()
        return f"encrypted = {ct}"

    def get_params(self):
        return f"p = {self.p}\ng = {self.g}\nA = {self.A}\nB = {self.B}"


def main():

    dh = DH()
    print(dh.get_params())
    print(dh.encrypt(FLAG))

if __name__ == "__main__":
    main()

p = 85013941328859365232686230728938372320812319905627686919070637645614632817039920673725615375841158719310596592903101914818137738460649589340349796188816568005092757847
g = 20033344683527080232439150682925185454003164954955126339094967675384779782733210350757021743656898625398860187361281262413493941502725149445995471514781822892886669776
A = 76548721461171533747911417838852759206858825205673491250696441734297318615226024320798706656529038703728631231084155790148283919370554345818139818854112841655270107839
B = 2103083080159597422706551446020625757109756570951674830166998494220734179439318911618156966499109201221652320384817270671579741987575328177442670242481963924501204498
encrypted = "240e7b7678aaaa0dcbe06de7c5598a1ca0be7e2ae584bc7dfd2388cdb1d4fb6a37ceb94556757afc293999cbe5a5a2dbb4071ebf6cfd4332088555f9b2de1922"
