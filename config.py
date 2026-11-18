# config.py
# Wspolna konfiguracja portow UDP, rozmiarow pol i parametrow kanalu

UDP_IP = "127.0.0.1"
GROUND_TO_CHANNEL_PORT = 5005
CHANNEL_TO_SATELLITE_PORT = 5006
BUFFER_SIZE = 65535

# Rozmiary pol ramki (w bajtach) zgodnie z Rys. 1B dokumentacji
CCSDS_HEADER_LEN = 6        # Naglowek glowny CCSDS SPP (jawny, AAD)
IV_PREFIX_LEN = 8           # Prefiks wektora IV (8 B)
ANTI_REPLAY_NONCE_LEN = 4   # Licznik Anti-Replay Nonce (4 B)
IV_TOTAL_LEN = 12           # Laczny rozmiar Nonce dla AES-GCM (8 + 4 = 12 B)
GCM_TAG_LEN = 16            # Tag uwierzytelniajacy MAC / GCM Tag (16 B)
CRYPTO_OVERHEAD_LEN = 28    # Laczny narzut kryptograficzny (12 B IV + 16 B MAC)

# Wspoldzielony klucz sesyjny AES-128 (16 bajtow = 128 bitow) oraz 8-bajtowy prefiks IV
PRE_SHARED_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
STATIC_IV_PREFIX = bytes.fromhex("a1b2c3d4e5f60718")

# Domyslne parametry symulatora kanalu satelitarnego
DEFAULT_LATENCY_MS = 15.0   # 15 ms dla LEO (250 ms dla GEO)
DEFAULT_PACKET_LOSS = 0.05  # 5% losowej utraty pakietow (fading)
DEFAULT_BER = 0.0001        # Stopa bledow bitowych (Bit Error Rate)
ANTI_REPLAY_WINDOW = 64     # Rozmiar okna akceptacji licznika na satelicie