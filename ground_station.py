# ground_station.py


import socket
import time
from config import UDP_IP, GROUND_TO_CHANNEL_PORT, CRYPTO_OVERHEAD_LEN
from ccsds_packet import CCSDSPrimaryHeader, assemble_secured_frame
from crypto_engine import CryptoContext

def run_ground_station():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    crypto = CryptoContext()

    sample_commands = [
        b"TC_OBC_PING",
        b"TC_ADCS_SET_NADIR_MODE",
        b"TC_EPS_ENABLE_HEATER_1"
    ]

    for seq_idx, payload in enumerate(sample_commands):
        # Liczba oktetow pola danych po naglowku glownym pomniejszona o 1: (N + 28) - 1 = N + 27
        ccsds_data_len = len(payload) + CRYPTO_OVERHEAD_LEN - 1
        header = CCSDSPrimaryHeader(
            packet_type=1, sec_hdr_flag=1, apid=0x010,
            seq_count=seq_idx, data_length=ccsds_data_len
        )
        header_bytes = header.pack()

        iv_bytes, ciphertext, mac_tag = crypto.protect_packet(header_bytes, payload)
        full_frame = assemble_secured_frame(header_bytes, iv_bytes, ciphertext, mac_tag)

        sock.sendto(full_frame, (UDP_IP, GROUND_TO_CHANNEL_PORT))
        print(f"[ZIEMIA] Wyslano TC #{seq_idx} | APID=0x{header.apid:03X} | Rozmiar={len(full_frame)} B | Ladunek={payload}")
        time.sleep(1.0)

if __name__ == "__main__":
    run_ground_station()