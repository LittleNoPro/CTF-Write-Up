import re

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

Zp = Zmod(p)
P256 = EllipticCurve(Zp, [a, b])

F.<key1, key2> = PolynomialRing(Zp)

with open("output.txt", "r") as f:
  outputs = re.findall(r'\d{10,}', f.read())
outputs = [list(map(int, outputs[i:i+4])) for i in range(0, len(outputs), 4)]

eqs = []

for o_a, o_b, o_c, o_d in outputs:
  Px = F(o_a * key1 + o_b)
  Qx = F(o_c * key2 + o_d)

  eqs.append((3*Px^2 + a)^2 - ((Qx + 2*Px)*(4*(Px^3 + a*Px + b))))

I = F.ideal(eqs)
key1, key2 = I.variety()[0][key1], I.variety()[0][key2]
print(f"DH{{{ZZ(key1) ^^ ZZ(key2):064x}}}")
