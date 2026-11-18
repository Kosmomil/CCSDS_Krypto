# CCSDS SPP + AEAD (AES-128-GCM) – Symulator Łącza Satelitarnego

Projekt rozszerzenia protokołu **CCSDS Space Packet Protocol (CCSDS 133.0-B-2)** o warstwę kryptograficzną wzorowaną na **CCSDS SDLS (CCSDS 355.0-B-2)** z wykorzystaniem szyfrowania uwierzytelnionego **AES-128-GCM**.

## Skład zespołu
* **Michał Kosmowski** – Warstwa protokołu CCSDS SPP oraz komunikacja sieciowa (Stacja Naziemna / Satelita)
* **Kamil Czapla** – Moduł kryptograficzny AES-128-GCM, ochrona AAD oraz mechanizm Anti-Replay
* **Maciej Oćwieja** – Symulator kanału satelitarnego (opóźnienie, Packet Loss, szum BER) i analiza wydajności

## Struktura zmodyfikowanej ramki (N + 34 bajtów)
1. **Nagłówek główny CCSDS SPP (6 B)** – jawny, chroniony przed modyfikacją jako AAD (Associated Authenticated Data).
2. **Wektor IV / Nonce (12 B)** – jawny: 8 B prefiksu sesyjnego + 4 B licznika Anti-Replay Nonce.
3. **Szyfrogram (N B)** – zaszyfrowane pole danych użytecznych (brak paddingu w trybie licznikowym GCM).
4. **Tag MAC / GCM Tag (16 B)** – 128-bitowy znacznik integralności i autentyczności.

## Uruchomienie środowiska
1. Instalacja zależności:
   ```bash
   pip install -r requirements.txt
