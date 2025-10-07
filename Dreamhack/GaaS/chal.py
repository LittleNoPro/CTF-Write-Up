from Crypto.Cipher import AES
import secrets
import json

random = secrets.SystemRandom()

# Ask admin to get the signature for this passcode
registered = set(["admin"])
ADMIN_PASSCODE = "This_is_super_safe_passcode_never_try_to_enter_q1w2w3r4"


class GaaS:
    def __init__(self, key: bytes | None = None, nonce: bytes | None = None):
        if key is None:
            key = random.randbytes(16)
        if nonce is None:
            nonce = random.randbytes(16)

        self.key = key
        self.nonce = nonce

    def sign(self, msg: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
        _, tag = cipher.encrypt_and_digest(msg)
        return tag

    def verify(self, msg: bytes, sig: bytes) -> bool:
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
        _, tag = cipher.encrypt_and_digest(msg)
        return tag == sig


def print_flag() -> None:
    with open("./flag", "r") as f:
        print(f"Flag: {f.read().strip()}")


def sign_up(gaas: GaaS) -> None:
    global registered

    username = input("Username: ")
    if username in registered:
        print("You already have signed up\n")
        return
    elif len(username) > 16:
        print("Too long!")
        exit(0)

    payload = json.dumps({"username": username}).encode("ascii")
    signature = gaas.sign(payload)
    registered.add(username)
    print(f"This is your token: {signature.hex()}")
    print("Please save the token somewhere!\n")


def sign_in(gaas: GaaS) -> tuple[str | None, bool]:
    username = input("Username: ")
    passcode = input("Passcode (Enter if none): ")
    token = bytes.fromhex(input("Token: ").strip())

    if passcode:
        payload = json.dumps({
            "username": username,
            "passcode": passcode
        }).encode("ascii")
    else:
        payload = json.dumps({"username": username}).encode("ascii")

    if gaas.verify(payload, token):
        is_admin = (username == "admin" and passcode == ADMIN_PASSCODE)
        print(f"Welcome, {username}!\n")
        return username, is_admin
    else:
        print("Failed to sign in\n")
        return None, False


def print_menu(username: str | None) -> None:
    if username:
        print(f"Hello, {username}!")
    print("================")
    print(" [1] Sign up    ")
    print(" [2] Sign in    ")
    if username:
        print(" [3] Log out    ")
    print(" [4] Gimme flag ")
    print(" [5] Exit       ")
    print("================")


def main():
    gaas = GaaS()
    username, is_admin = None, False
    while True:
        print_menu(username)
        sel = int(input("> "))

        if sel == 1:
            sign_up(gaas)
        elif sel == 2:
            username, is_admin = sign_in(gaas)
        elif sel == 3:
            username, is_admin = None, False
        elif sel == 4:
            if username and is_admin:
                print_flag()
            else:
                print("You do not have permission\n")
                exit(0)
        else:
            exit(0)


if __name__ == "__main__":
    main()