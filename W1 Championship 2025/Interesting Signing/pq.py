from Crypto.Util.number import *
from sage.all import *
import os, math, random

p = getPrime(512)
print("p =", p)
q = getPrime(512)
print("q =", q)
N = p * q
e = 65537
d = pow(e, -1, (p - 1) * (q - 1))

MSG = [os.urandom(32) for _ in range(6)]

N_fault = []
N_bytes = long_to_bytes(N)
for i in [10, 20, 30, 40, 50, 60]:
	N_fault.append(bytes([i]) + N_bytes[1:])
N_fault = [bytes_to_long(nf) for nf in N_fault]

sig_1 = []
for i in range(6):
    msg = bytes_to_long(MSG[i])
    sigma_p = pow(msg,d,p)
    sigma_q = pow(msg,d,q)
    alpha = q*pow(q,-1,p)
    beta = p*pow(p,-1,q)
    sig = (alpha*sigma_p + beta*sigma_q) % N
    sig_1.append(sig)

sig_2 = []
for i in range(6):
    msg = bytes_to_long(MSG[i])
    sigma_p = pow(msg,d,p)
    sigma_q = pow(msg,d,q)
    alpha = q*pow(q,-1,p)
    beta = p*pow(p,-1,q)
    sig = (alpha*sigma_p + beta*sigma_q) % N_fault[i]
    sig_2.append(sig)

# print("sig_1 =", sig_1)
# print("sig_2 =", sig_2)
# exit()

v = []
for i, (x,y) in enumerate(zip(sig_1,sig_2)):
    v_i = crt([x, y], [N, N_fault[i]])
    v.append(v_i)

I_d = Matrix.identity(6)
print(I_d)

l = 1024
r = 6
k1 = 2**32
d1 = r+1
base1 = list()
for i in range(0, r):
	vector = list()
	for j in range(0, d1):
		if j == 0:
			vector.append(k1*v[i])
		else:
			if j == i+1:
				vector.append(1)
			else:
				vector.append(0)
	base1.append(vector)
base1 = Matrix(ZZ, r, d1, base1)
print(base1)

reduced1 = base1.LLL()
print("rank of reduced1:", reduced1.rank())

for row in reduced1.rows():
    print(row,'\n')

k2 = 2**l
d2 = r-2+r
M = list()
base2 = list()
for i in range(0, r):
	vector = list()
	m_rows = list()
	for j in range(0, d2):
		if j < r-2:
			vector.append(k2*reduced1[j][i+1])
			m_rows.append(reduced1[j][i+1])
		else:
			if j == i + r - 2:
				vector.append(1)
			else:
				vector.append(0)
	base2.append(vector)
	M.append(m_rows)

base2 = Matrix(ZZ, r, d2, base2)
reduced2 = base2.LLL()
w1 = list()
w2 = list()
for i in range(0, r):
	w1.append(reduced2[0][r - 2 + i])
	w2.append(reduced2[1][r - 2 + i])

sol = [
	gcd(v[0]+w1[0], N),
	gcd(v[0]+w2[0], N),
	gcd(v[0]-w1[0], N),
	gcd(v[0]-w2[0], N),
	gcd(v[0]+(w1[0]+w2[0]), N),
	gcd(v[0]+(w1[0]-w2[0]), N),
	gcd(v[0]+(-w1[0]+w2[0]), N),
	gcd(v[0]+(-w1[0]-w2[0]), N),
]
for s in sol:
	if s != 1 and s != N and N%s == 0:
		print(s)
		print("Factoring success!!")
		break
else:
	print("Factoring is failed.")
	exit()