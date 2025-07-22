from sage.all import *
import os
from Crypto.Util.number import bytes_to_long
from collections import deque
from tqdm import trange

flag = os.getenv('FLAG', 'HCMUS-CTF{https://www.youtube.com/shorts/fM93HlH_uS8}').encode()
flag = flag.lstrip(b'HCMUS-CTF{')[:-1]


def compress(xs):
    if len(xs) == 1:
        return xs[0]
    if len(xs) == 2:
        return (xs[0] ** 2 + xs[1]) * (xs[0] > xs[1]) + (xs[1] ** 2 + xs[1] + xs[0]) * (xs[0] <= xs[1])
    return compress([compress(xs[:len(xs) // 2]), compress(xs[len(xs) // 2:])])

def decompress(x):
    res = deque([x])
    while len(res) != 32:
        cur = res.popleft()
        scur = floor(sqrt(cur))
        if cur - scur ** 2 < scur:
            res.append(cur - scur ** 2)
            res.append(scur)
        else:
            res.append(scur)
            res.append(cur - scur ** 2 - scur)
    return list(res)

C = ComplexField(2025)

output = C("-5.88527593235489299068321197110162074955398163751677026348878587678198563512096561374433713065788418007265351759191254499302991113598229544074637054969362436335635557283847686469403534264062755064264226760324727413456645593770517369605939554683530971047581959142431251746289551828698583245826835298605177641733689139644823667911326192211991130712173122484560474908703443263144970675699444229343236525361018880000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e406 - 1.14510127674642293258768185812190843178685054774447478502029523908515272836942614475637089629555172451193362862404862635674340063873426115607363166955428451778942399828804765252241526029141253661800872342514586580588449781582315239548335257760382190166233624452416993114173278501704273569433411675814950741076865817726888485777410843796570593972670141659275729920647696091038639092879155858055558870844865536000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e407*I")
cr = 84077755203692134399464789175892066511565940653195267224311741153937420137712
ucr = decompress(cr)
r1 = bytes_to_long(bytearray(ucr[:8][::-1])) + bytes_to_long(bytearray(ucr[8:16][::-1])) * I
r2 = bytes_to_long(bytearray(ucr[16:24][::-1])) + bytes_to_long(bytearray(ucr[24:][::-1])) * I

for l in trange(20, 60, 2):
    k1 = l // 2
    k2 = l - k1
    PR2, vs = PolynomialRing(C, names = [f'c_{i}' for i in range(k1)] + [f'd_{i}' for i in range(k2)]).objgens()
    cs, ds = vs[:k1], vs[k1:]
    vs = vector(PR2, cs) + vector(PR2, ds) * I
    mono = [r1 ** (k1 - i) * r2 ** i for i in range(k1)]
    poly_symbolic = sum(a * b for a, b in zip(vs, mono))
    poly_symbolic -= output

    S = Sequence([poly_symbolic])
    mat, v = S.coefficients_monomials()
    mat2 = []
    for r in mat.T:
        mat2.append([round(r[0].real_part()), round(r[0].imag_part())])

    mat2 = Matrix(ZZ, mat2)
    mat2 = mat2.augment(matrix.identity(mat2.nrows()))
    mat2[-1, -1] = -1

    lll = mat2.LLL()

    try:
        flag = bytearray(lll[0][2:-1])
        print(b'HCMUS-CTF{' + flag + b'}')
        break
    except:
        continue

# HCMUS-CTF{c0mpress_Mor3_Eleg4nt_PaiRIhg_fVnction_420}
