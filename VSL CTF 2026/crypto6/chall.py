import os
import random
import signal
import socket
import sys
import dataclasses

from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, getRandomInteger

BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║              ⚡ TEMPORAL STREAM ORACLE ⚡                      ║
║       Navigate the polynomial currents of time!               ║
╚═══════════════════════════════════════════════════════════════╝
"""

TEMPORAL_EXPONENT = 4095
TEMPORAL_ROUNDS = 30
TEMPORAL_BITS = 512
COEFFICIENT_BITS = 1024

# SACRED_TREASURE = os.getenv("FLAG", "VSL{REDACTED}")
SACRED_TREASURE = "VSL{fake_flag_for_testing_purposes_only}"
TIMELINE_SEED = SHA256.new(SACRED_TREASURE.encode()).digest()
while len(TIMELINE_SEED) < 623 * 4:
    TIMELINE_SEED += SHA256.new(TIMELINE_SEED).digest()
random.seed(TIMELINE_SEED)


def _generate_temporal_prime(bits):
    return getPrime(bits, randfunc=random.randbytes)


def _generate_temporal_integer(bits):
    return getRandomInteger(bits, randfunc=random.randbytes)


@dataclasses.dataclass
class TemporalFlowGenerator:
    flow_multiplier: int
    flow_offset: int
    temporal_power: int
    temporal_modulus: int
    current_state: int

    def advance_timeline(self):
        self.current_state = (
            self.flow_multiplier * self.current_state + self.flow_offset) % self.temporal_modulus
        return pow(self.current_state, self.temporal_power, self.temporal_modulus)


def _decode_temporal_message(temporal_flows, encrypted_message):
    assert len(encrypted_message) <= 128
    message_value = int.from_bytes(encrypted_message, "big")

    for flow in temporal_flows:
        temporal_output = flow.advance_timeline()
        message_value ^= temporal_output
        print(f"temporal_leak: {message_value}")
        message_value ^= flow.current_state

    return message_value.to_bytes(128, "big")


def handle_temporal_session(conn, addr):
    original_stdin = sys.stdin
    original_stdout = sys.stdout

    class SocketInput:
        def __init__(self, connection):
            self.connection = connection
            self.data_buffer = b""

        def readline(self):
            while b"\n" not in self.data_buffer:
                chunk = self.connection.recv(4096)
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
        signal.alarm(180)

        print(BANNER)

        flow_multiplier = _generate_temporal_integer(COEFFICIENT_BITS)
        flow_offset = _generate_temporal_integer(COEFFICIENT_BITS)
        p_temporal = _generate_temporal_prime(TEMPORAL_BITS)
        q_temporal = _generate_temporal_prime(TEMPORAL_BITS)
        temporal_modulus = p_temporal * q_temporal

        print(f"flow_multiplier = {flow_multiplier}")
        print(f"flow_offset = {flow_offset}")
        print(f"temporal_power = {TEMPORAL_EXPONENT}")
        print(f"temporal_modulus = {temporal_modulus}")
        print()

        temporal_flows = [
            TemporalFlowGenerator(
                flow_multiplier,
                flow_offset,
                TEMPORAL_EXPONENT,
                temporal_modulus,
                getRandomInteger(COEFFICIENT_BITS) % temporal_modulus
            )
            for _ in range(TEMPORAL_ROUNDS)
        ]

        print("⚡ The temporal streams are active!")
        print("⚡ Send your encrypted queries to navigate time...")
        print()

        while True:
            query = input("temporal_query> ").strip()
            if not query:
                continue

            try:
                encrypted_bytes = bytes.fromhex(query)
                decoded_message = _decode_temporal_message(
                    temporal_flows, encrypted_bytes)

                if decoded_message.lstrip(b"\x00") == b"Give me the flag!":
                    print()
                    print(
                        "╔═══════════════════════════════════════════════════════════════╗")
                    print(
                        "║          ⚡ TIMELINE MASTERED! ⚡                              ║")
                    print(
                        "╚═══════════════════════════════════════════════════════════════╝")
                    print(f"💎 Sacred Treasure: {SACRED_TREASURE}")
                    break

                print("⚡ The temporal message was unclear...")
                print()

            except Exception as e:
                print(f"⚠ Temporal distortion detected...")
                print()

    except Exception as e:
        print(f"⚠ Timeline collapsed...")
    finally:
        sys.stdin = original_stdin
        sys.stdout = original_stdout
        conn.close()


if __name__ == "__main__":
    temporal_gate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temporal_gate.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    temporal_gate.bind(("0.0.0.0", 6666))
    temporal_gate.listen(5)
    print("⚡ Temporal Stream Oracle listening on port 6666...")

    while True:
        seeker, seeker_addr = temporal_gate.accept()
        print(f"⚡ New temporal seeker from {seeker_addr}")
        handle_temporal_session(seeker, seeker_addr)



# VSL{P0lyn0m14l_GCD_H4lf_GCD_Bulk_0pt1m1z4t10n_T3mp0r4l_Str34m_0r4cl3_T1m3l1n3_M4st3ry_4ch13v3d}