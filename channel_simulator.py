# channel_simulator.py

import socket
import time
import random
from config import (
    UDP_IP, GROUND_TO_CHANNEL_PORT, CHANNEL_TO_SATELLITE_PORT,
    BUFFER_SIZE, DEFAULT_LATENCY_MS, DEFAULT_PACKET_LOSS, DEFAULT_BER
)

def apply_bit_errors(frame: bytes, ber: float) -> tuple[bytes, int]:
    """Przeklamuje pojedyncze bity w ramce zgodnie z zadanym prawdopodobienstwem BER."""
    if ber <= 0.0:
        return frame, 0
    corrupted = bytearray(frame)
    flipped_bits = 0
    for byte_idx in range(len(corrupted)):
        for bit_idx in range(8):
            if random.random() < ber:
                corrupted[byte_idx] ^= (1 << bit_idx)
                flipped_bits += 1
    return bytes(corrupted), flipped_bits

def run_channel_simulator(latency_ms: float = DEFAULT_LATENCY_MS,
                          loss_prob: float = DEFAULT_PACKET_LOSS,
                          ber: float = DEFAULT_BER):
    rx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx_sock.bind((UDP_IP, GROUND_TO_CHANNEL_PORT))
    tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"[KANAL] Nasluch na {UDP_IP}:{GROUND_TO_CHANNEL_PORT} -> Przekazywanie na :{CHANNEL_TO_SATELLITE_PORT}")
    print(f"[KANAL] Parametry: Opóźnienie={latency_ms}ms | Packet Loss={loss_prob*100:.1f}% | BER={ber}")

    while True:
        frame, addr = rx_sock.recvfrom(BUFFER_SIZE)
        if random.random() < loss_prob:
            print(f"[KANAL] UTRATA PAKIETU (Fading) - ramka ({len(frame)} B) zgubiona.")
            continue

        time.sleep(latency_ms / 1000.0)
        noisy_frame, flips = apply_bit_errors(frame, ber)
        print(f"[KANAL] Przekazano ramke ({len(frame)} B) | Przeklamane bity (BER): {flips}")
        tx_sock.sendto(noisy_frame, (UDP_IP, CHANNEL_TO_SATELLITE_PORT))

if __name__ == "__main__":
    run_channel_simulator()