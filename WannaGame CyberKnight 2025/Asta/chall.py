from md128 import md128
import os
import random
import json

class Vuln(object):
    def __init__(self):
        self.secret = os.urandom(random.randint(1, 100))
    def register(self, username):
        token = f'username={username}||admin=False'
        return {"hash" : md128(self.secret + token.encode()).hex()}
    def login(self, token, hash):
        if md128(self.secret + token) == hash:

            if b'admin=True' in token:
                flag = open("flag.txt",'r').read()
                return {"msg" : f"Wellcome admin, this flag is for you: {flag}"}
            else:
                return {"msg" : f'You are not admin, no flag for you'}
        else:
            return {"msg" : "Login failed"}
def handle_input(vuln, inp):
    if 'action' not in inp:
        return {"error" : "Invalid option"}
    elif inp["action"] == "register":
        if 'username' not in inp:
            return {"error" : "Pls provide username!!!"}
        else:
            if 'admin' in inp['username']:
                return {"error" : "No injection pls!!!"}
            else:
                return vuln.register(inp['username'])
    elif inp["action"] == "login":
        if 'token' not in inp or 'hash' not in inp:
            return {"error" : "Token and hash are needed to login"}
        else:
            try:
                token = bytes.fromhex(inp['token'])
                hash = bytes.fromhex(inp['hash'])
                return vuln.login(token, hash)
            except:
                return {"error" : "Oops!!!"}
    else:
        return {"error" : f"Action {inp['action']} is not provided!!!"}

if __name__ == '__main__':
    vuln = Vuln()
    print('Login as admin to get flag!!!')
    while 1:
        try:
            inp = json.loads(input())
        except:
            print("Invalid json!!!")
            exit()
        # print(response)
        response = handle_input(vuln, inp)
        print(json.dumps(response))
        if 'error' in response:
            exit()