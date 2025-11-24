from pwn import *
from z3 import *
import time

io = remote('challs.glacierctf.com', 13375, level='debug')

TAGS = ["crypto", "misc", "pwn", "rev", "web"]

def get_winning_move(computer_idx):
    for p in range(5):
        j1 = (p + 1) % 5
        j2 = (p + 3) % 5
        if j1 == computer_idx or j2 == computer_idx:
            return TAGS[p]
    return TAGS[0]

def z3_lfsr_step(state):
    bit = (state ^ LShR(state, 3) ^ LShR(state, 7)) & 1
    new_state = LShR(state, 1) | (bit << 63)
    return new_state

def python_lfsr_step(state):
    bit = (state ^ (state >> 3) ^ (state >> 7)) & 1
    state = (state >> 1) | (bit << 63)
    return state & 0xffffffffffffffff

def solve():
    try:
        io.recvuntil(b"new-comer goodies.\n")

        solver = Solver()
        state_0 = BitVec('state_0', 64)
        current_state = state_0

        my_choice_str = TAGS[0].encode()

        start_time = time.time()

        for i in range(100):
            output_val = current_state & 0xf

            io.sendlineafter(b": ", my_choice_str)
            res = io.recvline().strip().decode()

            if res == "tie":
                solver.add(output_val % 5 == 0)
            elif res == "win":
                solver.add(Or(output_val % 5 == 1, output_val % 5 == 3))
            elif res == "lose":
                solver.add(Or(output_val % 5 == 2, output_val % 5 == 4))

            for _ in range(4):
                current_state = z3_lfsr_step(current_state)

        if solver.check() != sat:
            print("No solution found")
            return

        model = solver.model()
        recovered_state = model[state_0].as_long() & 0xffffffffffffffff
        print(f"State: {hex(recovered_state)}")

        real_state = recovered_state
        for _ in range(100):
            for _ in range(4):
                real_state = python_lfsr_step(real_state)

        winning_moves = []

        for i in range(200):
            val = real_state & 0xf
            comp_choice_idx = val % 5

            for _ in range(4):
                real_state = python_lfsr_step(real_state)

            move = get_winning_move(comp_choice_idx)
            winning_moves.append(move)

        payload = "\n".join(winning_moves)

        io.sendline(payload.encode())

        io.interactive()

    except EOFError:
        print("EOFError")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    solve()