from os import urandom
from Crypto.Cipher import AES
from ecdsa import SigningKey, NIST384p
from hashlib import sha256

sk = SigningKey.generate(curve=NIST384p)
vk = sk.verifying_key
idx = 0

class Server:
    def __init__(self):
        self.key = urandom(16)
        pass

    def key_rotation(self):
        global idx
        idx = (idx + 16) % 256
        self.key = urandom(16)
        print("current Server key: ", self.key.hex())


    def decrypt(self, enc_msg):
        key = self.key
        nonce = enc_msg[:12]
        ct = enc_msg[12:-16]
        tag = enc_msg[-16:]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        msg = cipher.decrypt_and_verify(ct, tag)
        return msg

    def sign(self, enc_msg):
        msg = self.decrypt(enc_msg)
        if b'admin = True' in msg:
            raise ValueError("You are not allowed to sign admin messages!")

        if b'admin = False' not in msg[idx:idx+16]:
            raise ValueError("Invalid message format!")

        return sk.sign(enc_msg, hashfunc=sha256)


class FlagKeeper:
    def __init__(self, flag):
        self.flag = flag
        self.key = urandom(16)

    def key_rotation(self):
        global idx
        idx = (idx-16) % 256
        self.key = urandom(16)
        print("current FlagKeeper key: ", self.key.hex())

    def get_flag(self, enc_msg, signature):
        try:
            vk.verify(signature, enc_msg, hashfunc=sha256)
        except:
            raise ValueError("Invalid signature!")

        key = self.key
        nonce = enc_msg[:12]
        ct = enc_msg[12:-16]
        tag = enc_msg[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        msg = cipher.decrypt_and_verify(ct, tag)
        if b'admin = True' in msg[:idx] and b'admin = False' not in msg:
            return self.flag
        else:
            return b'No flag for you!'


def main():
    flag = open("flag.txt", "rb").read().strip()
    fk = FlagKeeper(flag)
    server = Server()

    print("Welcome to the secure server!")
    print("You can use the following services:")
    print("1. Rotate Server's keys ")
    print("2. Rotate FlagKeeper's keys ")
    print("3. Sign a message (except admin = True)")
    print("4. Get the flag (only if your message contains admin = True)")
    print("5. Exit")

    for _ in range(5):
        try:
            choice = int(input("Enter your choice: "))
            if choice == 1:
                server.key_rotation()

            elif choice == 2:
                fk.key_rotation()

            elif choice == 3:
                enc_msg = bytes.fromhex(input("Enter the encrypted message (in hex): "))
                signature = server.sign(enc_msg)
                print("Signature (in hex):", signature.hex())

            elif choice == 4:
                enc_msg = bytes.fromhex(input("Enter the encrypted message (in hex): "))
                signature = bytes.fromhex(input("Enter the signature (in hex): "))
                flag = fk.get_flag(enc_msg, signature)
                print("Flag:", flag.decode())

            elif choice == 5:
                print("Goodbye!")
                break
            else:
                print("Invalid choice!")
        except Exception as e:
            print("Error:", str(e))

if __name__ == "__main__":
    main()