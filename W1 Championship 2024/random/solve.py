import random

ct = "0203e2c0dd20182bea1d00f41b25ad314740c3b239a32755bab1b3ca1a98f0127f1a1aeefa15a418e9b03ad25b3a92a46c0f5a6f41cb580f7d8a3325c76e66b937baea"
ct = bytes.fromhex(ct)

for seed in range(10000):
    random.seed(seed)
    flag = list(ct)

    for _ in range(1337):
        ran = [random.randint(0, 255) for _ in range(len(flag))]
        flag = [x ^ y for x, y in zip(flag, ran)]

    flag = bytes(flag)
    if b"W1{" in flag:
        print(flag)
        break

# Flag: W1{maybe_the_seed_is_too_small..._b32fe938a402c22144b9d6497fd5a709}
