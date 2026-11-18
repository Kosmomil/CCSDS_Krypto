# crypto_engine.py


import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from config import PRE_SHARED_KEY, STATIC_IV_PREFIX, ANTI_REPLAY_WINDOW

class CryptoContext:
    def __init__(self, key: bytes = PRE_SHARED_KEY, iv_prefix: bytes = STATIC_IV_PREFIX):
        self.aesgcm = AESGCM(key)
        self.iv_prefix = iv_prefix
        self.tx_nonce_counter = 0      # Licznik nadawczy (Stacja Naziemna)
        self.rx_last_valid_nonce = -1  # Ostatni zaakceptowany licznik (Satelita)

    def build_iv(self, nonce_counter: int) -> bytes:
        """Buduje 12-bajtowy wektor IV: 8B Prefiks + 4B Licznik Anti-Replay (Big-Endian)."""
        return self.iv_prefix + struct.pack(">I", nonce_counter & 0xFFFFFFFF)

    @staticmethod
    def extract_nonce_counter(iv_bytes: bytes) -> int:
        """Odczytuje 4-bajtowy licznik Anti-Replay z konca 12-bajtowego pola IV."""
        return struct.unpack(">I", iv_bytes[8:12])[0]

    def protect_packet(self, ccsds_header_aad: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
        """
        Szyfruje ladunek (AES-128-GCM) i uwierzytelnia 6-bajtowy naglowek CCSDS jako AAD.
        Zwraca krotke: (iv_12B, ciphertext, mac_tag_16B).
        """
        self.tx_nonce_counter += 1
        iv_bytes = self.build_iv(self.tx_nonce_counter)
        # AESGCM.encrypt zwraca sklejony (szyfrogram + 16B tag MAC)
        ct_and_tag = self.aesgcm.encrypt(iv_bytes, plaintext, ccsds_header_aad)
        ciphertext = ct_and_tag[:-16]
        mac_tag = ct_and_tag[-16:]
        return iv_bytes, ciphertext, mac_tag

    def verify_and_decrypt(self, ccsds_header_aad: bytes, iv_bytes: bytes, ciphertext: bytes, mac_tag: bytes) -> bytes:
        """
        Weryfikuje okno Anti-Replay oraz tag MAC (w tym integralnosc naglowka AAD).
        Aktualizuje stan licznika tylko po pozytywnej weryfikacji kryptograficznej.
        """
        received_nonce = self.extract_nonce_counter(iv_bytes)

        # 1. Weryfikacja Anti-Replay (licznik musi byc scisle wiekszy od ostatniego poprawnego)
        if received_nonce <= self.rx_last_valid_nonce:
            raise ValueError(f"Atak Replay wykryty! Odebrany Nonce={received_nonce} <= {self.rx_last_valid_nonce}")
        if self.rx_last_valid_nonce >= 0 and (received_nonce - self.rx_last_valid_nonce) > ANTI_REPLAY_WINDOW:
            raise ValueError(f"Nonce={received_nonce} poza oknem synchronizacji ({ANTI_REPLAY_WINDOW}).")

        # 2. Weryfikacja tagu MAC (AAD + Szyfrogram) oraz deszyfracja
        try:
            plaintext = self.aesgcm.decrypt(iv_bytes, ciphertext + mac_tag, ccsds_header_aad)
        except InvalidTag as exc:
            raise ValueError("Blad weryfikacji MAC (InvalidTag) - przeklamanie bitu lub manipulacja ramka!") from exc

        # 3. Aktualizacja licznika dopiero po pelnym sukcesie
        self.rx_last_valid_nonce = received_nonce
        return plaintext