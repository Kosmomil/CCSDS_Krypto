# ccsds_packet.py
# Autor: Michal Kosmowski - Warstwa protokolu CCSDS SPP (CCSDS 133.0-B-2)

import struct
from dataclasses import dataclass
from config import CCSDS_HEADER_LEN, IV_TOTAL_LEN, GCM_TAG_LEN

@dataclass
class CCSDSPrimaryHeader:
    version: int = 0            # 3 bity: zawsze 000
    packet_type: int = 1        # 1 bit: 0 = TM (Telemetria), 1 = TC (Telekomenda)
    sec_hdr_flag: int = 1       # 1 bit: 1 = obecnosc naglowka bezpieczenstwa
    apid: int = 0x010           # 11 bitow: identyfikator procesu (0 - 2047)
    seq_flags: int = 0b11       # 2 bity: 11 = pakiet niesegmentowany
    seq_count: int = 0          # 14 bitow: licznik sekwencji pakietu PSC (modulo 16384)
    data_length: int = 0        # 16 bitow: (liczba oktetow pola danych - 1)

    def pack(self) -> bytes:
        """Serializuje 6-bajtowy naglowek glowny CCSDS w porzadku Big-Endian."""
        word0 = ((self.version & 0x07) << 13) | \
                ((self.packet_type & 0x01) << 12) | \
                ((self.sec_hdr_flag & 0x01) << 11) | \
                (self.apid & 0x07FF)
        word1 = ((self.seq_flags & 0x03) << 14) | \
                (self.seq_count & 0x3FFF)
        word2 = self.data_length & 0xFFFF
        return struct.pack(">HHH", word0, word1, word2)

    @classmethod
    def unpack(cls, raw_bytes: bytes) -> "CCSDSPrimaryHeader":
        """Deserializuje 6 bajtow do obiektu naglowka CCSDSPrimaryHeader."""
        if len(raw_bytes) < CCSDS_HEADER_LEN:
            raise ValueError("Ramka krotsza niz 6-bajtowy naglowek CCSDS.")
        word0, word1, word2 = struct.unpack(">HHH", raw_bytes[:CCSDS_HEADER_LEN])
        return cls(
            version=(word0 >> 13) & 0x07,
            packet_type=(word0 >> 12) & 0x01,
            sec_hdr_flag=(word0 >> 11) & 0x01,
            apid=word0 & 0x07FF,
            seq_flags=(word1 >> 14) & 0x03,
            seq_count=word1 & 0x3FFF,
            data_length=word2
        )

def assemble_secured_frame(header_bytes: bytes, iv_bytes: bytes, ciphertext: bytes, mac_tag: bytes) -> bytes:
    """Sklada kompletna ramke: 6B Naglowek + 12B IV + N B Szyfrogram + 16B MAC."""
    return header_bytes + iv_bytes + ciphertext + mac_tag

def disassemble_secured_frame(frame_bytes: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Rozklada odebrana ramke na: (header_6B, iv_12B, ciphertext, mac_16B)."""
    min_len = CCSDS_HEADER_LEN + IV_TOTAL_LEN + GCM_TAG_LEN
    if len(frame_bytes) < min_len:
        raise ValueError(f"Ramka uszkodzona: dlugosc {len(frame_bytes)} B (minimum {min_len} B).")
    header_bytes = frame_bytes[:CCSDS_HEADER_LEN]
    iv_bytes = frame_bytes[CCSDS_HEADER_LEN : CCSDS_HEADER_LEN + IV_TOTAL_LEN]
    ciphertext = frame_bytes[CCSDS_HEADER_LEN + IV_TOTAL_LEN : -GCM_TAG_LEN]
    mac_tag = frame_bytes[-GCM_TAG_LEN:]
    return header_bytes, iv_bytes, ciphertext, mac_tag