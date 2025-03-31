from sage.all import *

p = 0x31337313373133731337313373133731337313373133731337313373133732ad
a = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
b = 0xdeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0de
hint1 = 77759147870011250959067600299812670660963056658309113392093130
hint2 = 50608194198883881938583003429122755064581079722494357415324546

# H1 = hint1 << 48 + h1
# H2 = hint2 << 48 + h2

h1, h2 = var('h1 h2')
f = (hint1 * (1 << 48) + h1) * (hint2 * (1 << 48) + h2) * (-a**3 - a**2) + (hint2 * (1 << 48) + h2) * (a**3 + a**2 + a) + (hint1 * (1 << 48) + h1) * a**2 - a**2 - a

sols = solve_mod(f, p)

print(sols)