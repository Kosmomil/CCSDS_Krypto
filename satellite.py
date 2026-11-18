# satellite.py


import socket
from config import UDP_IP, CHANNEL_TO_SATELLITE_PORT, BUFFER_SIZE
from ccsds_packet import CCSDSPrimaryHeader, disassemble_secured_frame
from crypto_engine import CryptoContext

def run_satellite():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, CHANNEL_TO_SATELLITE_PORT))
    crypto = CryptoContext()

    print(f"[SATELITA] Oczekiwanie na zabezpieczone ramki CCSDS na porcie {CHANNEL_TO_SATELLITE_PORT}...")

    while True:
        frame_bytes, addr = sock.recvfrom(BUFFER_SIZE)
        try:
            hdr_bytes, iv_bytes, ciphertext, mac_tag = disassemble_secured_frame(frame_bytes)
            header = CCSDSPrimaryHeader.unpack(hdr_bytes)
            plaintext = crypto.verify_and_decrypt(hdr_bytes, iv_bytes, ciphertext, mac_tag)
            nonce_val = crypto.extract_nonce_counter(iv_bytes)
            print(f"[SATELITA] [OK] APID=0x{header.apid:03X} | PSC={header.seq_count} | Nonce={nonce_val} | Dane={plaintext.decode('utf-8', errors='replace')}")
        except ValueError as err:
            print(f"[SATELITA] [ODRZUCENIE RAMKI] Powod: {err}")

if __name__ == "__main__":
    run_satellite()