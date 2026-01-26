from pwn import *
from Crypto.Util.number import *
from sage.all import *
from tqdm import *

def _GCD(a, b):
    while not b.is_zero():
        _, r = a.quo_rem(b)
        a, b = b, r
    return a.monic()

io = remote('localhost', 6666, level='debug')

io.recvuntil(b'flow_multiplier = ')
flow_multiplier = int(io.recvline().strip())
io.recvuntil(b'flow_offset = ')
flow_offset = int(io.recvline().strip())
io.recvuntil(b'temporal_power = ')
temporal_power = int(io.recvline().strip())
io.recvuntil(b'temporal_modulus = ')
temporal_modulus = int(io.recvline().strip())

def next_state(current_state):
    return (flow_multiplier * current_state + flow_offset) % temporal_modulus

def send_query(data: bytes) -> None:
    io.sendlineafter(b'temporal_query> ', data.hex().encode())
    leaks = []
    for _ in range(30):
        io.recvuntil(b'temporal_leak: ')
        leak = int(io.recvline().strip())
        leaks.append(leak)
    return leaks

leaks_0 = send_query(b'\x00' * 1)
leaks_1 = send_query(b'\x00' * 1)

state_0 = [0] * 30
x = PolynomialRing(Zmod(temporal_modulus), 'x').gen()
fx = x**temporal_power - leaks_0[0]
gx = (flow_multiplier * x + flow_offset)**temporal_power - leaks_1[0]
sols = _GCD(fx, gx)

if sols.degree() == 1:
    state_0[0] = -int(sols[0]) * inverse_mod(int(sols[1]), temporal_modulus) % temporal_modulus

message_value_0 = pow(state_0[0], temporal_power, temporal_modulus) ^ state_0[0]
message_value_1 = pow(next_state(state_0[0]), temporal_power, temporal_modulus) ^ next_state(state_0[0])
for i in trange(1, 30):
    temporal_output_0 = message_value_0 ^ leaks_0[i]
    temporal_output_1 = message_value_1 ^ leaks_1[i]

    fx = x**temporal_power - temporal_output_0
    gx = (flow_multiplier * x + flow_offset)**temporal_power - temporal_output_1
    sols = _GCD(fx, gx)

    if sols.degree() == 1:
        state_0[i] = -int(sols[0]) * inverse_mod(int(sols[1]), temporal_modulus) % temporal_modulus

    message_value_0 ^= pow(state_0[i], temporal_power, temporal_modulus) ^ state_0[i]
    message_value_1 ^= pow(next_state(state_0[i]), temporal_power, temporal_modulus) ^ next_state(state_0[i])

current_state = [next_state(s) for s in state_0]

target = b'Give me the flag!'
target = int.from_bytes(target, 'big')
for i in range(30):
    current_state[i] = next_state(current_state[i])
    target ^= pow(current_state[i], temporal_power, temporal_modulus) ^ current_state[i]

io.sendlineafter(b'temporal_query> ', target.to_bytes(128, 'big').hex().encode())
io.recvall()