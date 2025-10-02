from Crypto.Cipher import AES
import base64
import json
import os

key = os.urandom(16)
users = set()
session = None

def register():
    global users

    name = input('Name: ').strip()
    if name in users:
        print("You can register twice")
        return
    users.add(name)

    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    data = json.dumps({"name": name, "isAdmin": False})
    data = data.encode()
    data += b'\x00' * (-len(data) % 16)

    enc = iv + cipher.encrypt(data)
    token = base64.b64encode(enc).decode()

    print(f"Here is your token: {token}")

def login_or_out():
    global session, users

    if session:
        session = None
        print("Logged out")
        return

    name = input('Name: ').strip()
    token = input('Token: ').strip()

    if name not in users:
        print("Please register first")
        return

    token_data = base64.b64decode(token)
    iv, enc = token_data[:16], token_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    res = cipher.decrypt(enc)

    res = res[:res.rfind(b'}') + 1]
    try:
        data = json.loads(res.decode('utf-8', 'ignore'))
        assert data['name'] == name, "Name is different"
        assert len(res) <= 24, "Too long"
    except Exception as e:
        print(e)
        return

    session = data
    print(f"Welcome, {name}!")

def print_flag():
    global session

    if session is None or not session['isAdmin']:
        print("No.")
        return

    with open('./flag', 'r') as f:
        print(f.read())

def print_menu():
    global session
    print("1. Register")
    if session is None:
        print("2. Log in")
    else:
        print("2. Log out")
    print("3. Print the flag")

def main():

    while True:
        print_menu()
        try:
            choice = int(input('> '))
        except:
            print("Wrong choice")
            return

        if choice == 1:
            register()
        elif choice == 2:
            login_or_out()
        elif choice == 3:
            print_flag()

if __name__ == "__main__":
    main()
