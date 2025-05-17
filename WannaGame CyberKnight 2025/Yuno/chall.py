import os, md128
target = os.urandom(16)
print(target.hex())
if md128.md128(bytes.fromhex(input())) == target:
	print(open("flag.txt", "r").read())
else:
	print("WTF!!!")