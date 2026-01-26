import os
import random
import signal
import socket
import sys
import hashlib
import string
from functools import lru_cache

BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║                    🐉 DRAGON SLAYER 🗡️                        ║
║         Defeat the Ancient Dragon using Nimber Magic!         ║
╚═══════════════════════════════════════════════════════════════╝
"""


@lru_cache
def _quantum_field_multiply(val_x, val_y, bit_width=512):
    assert val_x.bit_length() <= bit_width and val_y.bit_length() <= bit_width
    if val_x == 0 or val_y == 0:
        return 0
    if val_x == 1:
        return val_y
    if val_y == 1:
        return val_x
    bit_width >>= 1
    high_x, low_x = val_x >> bit_width, val_x & (1 << bit_width) - 1
    high_y, low_y = val_y >> bit_width, val_y & (1 << bit_width) - 1
    low_product = _quantum_field_multiply(low_x, low_y, bit_width)
    high_product = _quantum_field_multiply(high_x, high_y, bit_width)
    cross_sum = _quantum_field_multiply(
        high_x ^ low_x, high_y ^ low_y, bit_width) ^ low_product
    fermat_term = _quantum_field_multiply(
        1 << (bit_width - 1), high_product, bit_width) ^ low_product
    return cross_sum << bit_width | fermat_term


class QuantumNimber:
    def __init__(self, essence):
        self.essence = essence

    def __add__(self, other):
        return QuantumNimber(self.essence ^ other.essence)

    def __sub__(self, other):
        return QuantumNimber(self.essence ^ other.essence)

    def __mul__(self, other):
        return QuantumNimber(_quantum_field_multiply(self.essence, other.essence))

    def __pow__(self, exponent):
        assert exponent >= 0
        base = self
        result = QuantumNimber(1)
        while exponent > 0:
            if exponent % 2 == 1:
                result = result * base
            base *= base
            exponent //= 2
        return result

    def __repr__(self):
        return str(self.essence)


def generate_pow_challenge():
    prefix = ''.join(random.choices(
        string.ascii_lowercase + string.digits, k=8))
    difficulty = 4
    return prefix, difficulty


def verify_pow(prefix, solution, difficulty):
    combined = prefix + solution
    hash_result = hashlib.sha256(combined.encode()).hexdigest()
    return hash_result.startswith('0' * difficulty)


def handle_dragon_battle(conn, addr):
    original_stdin = sys.stdin
    original_stdout = sys.stdout

    class SocketInput:
        def __init__(self, connection):
            self.connection = connection
            self.data_buffer = b""

        def readline(self):
            while b"\n" not in self.data_buffer:
                chunk = self.connection.recv(1024)
                if not chunk:
                    return ""
                self.data_buffer += chunk
            line, self.data_buffer = self.data_buffer.split(b"\n", 1)
            return line.decode()

    class SocketOutput:
        def __init__(self, connection):
            self.connection = connection

        def write(self, message):
            self.connection.sendall(
                message.encode() if isinstance(message, str) else message)

        def flush(self):
            pass

    sys.stdin = SocketInput(conn)
    sys.stdout = SocketOutput(conn)

    try:
        signal.alarm(120)
        secret_treasure = os.environ.get("FLAG", "VSL{REDACTED}")
        print(BANNER)
        print("🔮 Before entering the dragon's lair, prove your worth!")
        pow_prefix, pow_difficulty = generate_pow_challenge()
        print(
            f"Find a string S such that SHA256('{pow_prefix}' + S) starts with {pow_difficulty} zeros")
        print(f"Challenge: {pow_prefix}")
        pow_solution = input("Your proof: ").strip()
        if not verify_pow(pow_prefix, pow_solution, pow_difficulty):
            print("❌ Invalid proof! The dragon's lair remains sealed.")
            conn.close()
            return
        print("✅ Proof accepted! The dragon's lair opens...")
        print()
        magic_power = QuantumNimber(random.getrandbits(512))
        dragon_life = QuantumNimber(random.getrandbits(512))
        print(f"⚔️ Your Magic Power: {magic_power}")
        print("🔥 The Ancient Dragon appears! Cast your spells wisely!")
        print()
        max_spells = 4
        for spell_count in range(max_spells):
            print(f"━━━ Spell Cast #{spell_count + 1}/{max_spells} ━━━")
            print(f"🐉 Dragon's Life Force: {dragon_life}")
            spell_intensity = int(input("⚡ Spell Intensity> "))
            assert 0 <= spell_intensity < 2**512, "Invalid spell intensity!"
            damage = magic_power ** spell_intensity
            dragon_life = dragon_life - damage
            if dragon_life.essence == 0:
                print()
                print(
                    "╔═══════════════════════════════════════════════════════════════╗")
                print("║              🎉 VICTORY! THE DRAGON IS SLAIN! 🎉              ║")
                print(
                    "╚═══════════════════════════════════════════════════════════════╝")
                print(f"💎 Ancient Treasure: {secret_treasure}")
                conn.close()
                return
            print(f"💥 You dealt damage! Dragon survives with remaining life force...")
            print()
        print()
        print("💀 The dragon overwhelms you with its fiery breath...")
        print("Game Over - The dragon lives on!")
    except Exception as e:
        print(f"⚠️ An error occurred in the mystical realm...")
    finally:
        sys.stdin = original_stdin
        sys.stdout = original_stdout
        conn.close()


if __name__ == "__main__":
    battle_arena = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    battle_arena.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    battle_arena.bind(("0.0.0.0", 6669))
    battle_arena.listen(5)
    print("🐉 Dragon Slayer server listening on port 6669...")
    while True:
        challenger, challenger_addr = battle_arena.accept()
        print(f"⚔️ New challenger from {challenger_addr}")
        handle_dragon_battle(challenger, challenger_addr)