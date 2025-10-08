ct = "2f01090a6f042b4447101f0047460d6e0e5d001100422d156443022c4a3e074a392b033e531d1b47401b44423c411e08"
ct = bytes.fromhex(ct)

ALPHABET = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}_"

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

state = [(b"W1{" + b"\x00" * (len(ct) - 3), 0)]
for _ in range(len(ct) // 3 - 1):
    new_state = []
    for flag, idx in state:
        keystream = xor(flag[idx:idx+3], ct[idx:idx+3])

        for i in range(0, len(ct), 3):
            if flag[i:i+3] != b"\x00\x00\x00":
                continue

            _ct = xor(keystream, ct[i:i+3])
            if all(c in ALPHABET for c in _ct):
                new_flag = flag[:i] + keystream + flag[i+3:]
                new_state.append((new_flag, i))

    state = new_state

for flag, _ in state:
    if flag.endswith(b"}") and flag.count(b"{") == 1 and flag.count(b"}") == 1:
        print(flag)