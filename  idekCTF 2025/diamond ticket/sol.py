from sage.all import *
from Crypto.Util.number import *
from cpmpy import *
from tqdm import trange
import re

N = 85494791395295332945307239533692379607357839212287019473638934253301452108522067416218735796494842928689545564411909493378925446256067741352255455231566967041733698260315140928382934156213563527493360928094724419798812564716724034316384416100417243844799045176599197680353109658153148874265234750977838548867
c1 = 27062074196834458670191422120857456217979308440332928563784961101978948466368298802765973020349433121726736536899260504828388992133435359919764627760887966221328744451867771955587357887373143789000307996739905387064272569624412963289163997701702446706106089751532607059085577031825157942847678226256408018301
c2 = 30493926769307279620402715377825804330944677680927170388776891152831425786788516825687413453427866619728035923364764078434617853754697076732657422609080720944160407383110441379382589644898380399280520469116924641442283645426172683945640914810778133226061767682464112690072473051344933447823488551784450844649
p = 170829625398370252501980763763988409583
a = 164164878498114882034745803752027154293
b = 125172356708896457197207880391835698381
e = bytes_to_long(b"idek{this_is_a_fake_flag_lolol}")

def gcdExtended(a, b):
    if a == 0 :
        return b,0,1
    gcd,x1,y1 = gcdExtended(b%a, a)
    x = y1 - (b//a) * x1
    y = x1
    return gcd,x,y

_, a, b = gcdExtended(e, 2)
m = pow(c1, a, N) * pow(c2, b, N) % N

def split_remain_bytes(remain_bytes: bytes, chunk_size=p.bit_length() // 8):
    chunks = [remain_bytes[i:i+chunk_size] for i in range(0, len(remain_bytes), chunk_size)]
    return [bytes_to_long(chunk) for chunk in chunks]

remain_numbers = split_remain_bytes(long_to_bytes(m))
flag_chocolate = remain_numbers[-1]

p = 170829625398370252501980763763988409583
a = 164164878498114882034745803752027154293
b = 125172356708896457197207880391835698381
flag_chocolate = 99584795316725433978492646071734128819

F = GF(p)
k = F(b).log(a)
assert pow(a, k, p) == b

# x = PolynomialRing(GF(p), 'x').gen()
# fx = x + x**k - flag_chocolate
# fx = fx.gcd(pow(x, (p - 1) // 2 + 1, fx) - x).roots(multiplicities=False)
# m0 = F(fx[0]).log(a)

# assert (pow(a, m0, p) + pow(b, m0, p)) % p == flag_chocolate % p

m0 = 4807895356063327854843653048517090061 # 122 bit
start = m0
ord_a = (p - 1) // 2

def solve_for_rem(start, rem):
		x = start + ord_a * (rem + 2**33 // os.cpu_count() * os.cpu_count() + os.cpu_count())
		jump = ord_a * os.cpu_count()
		while x >= 0:
			try:
				flag = long_to_bytes(x)
				if 33 <= min(flag) and max(flag) <= 122:
					print("idek{" + flag.decode() + "}")
			except Exception as e:
				pass
			x -= jump
		return None

import os
from concurrent.futures import ProcessPoolExecutor
with ProcessPoolExecutor(os.cpu_count()) as executor:
    for flag in executor.map(solve_for_rem, [start] * os.cpu_count(), range(os.cpu_count())):
        pass

