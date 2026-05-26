#!/usr/bin/env python3
"""Debug v4 - analyze the giant operation."""
import sys
sys.path.insert(0, 'src')
from analizador_smb2_v4 import leer_csv

paquetes = leer_csv('Trazas/Traza_user_5.csv')

# Show packets around L37 (the problematic CREATE)
print("=== Packets around L37 (root without CLOSE) ===")
for pk in paquetes:
    if 35 <= pk.linea <= 50:
        print(f"  L{pk.linea:4d} {pk.comando:16s} FID={str(pk.file_id or ''):30s} t={pk.timestamp:.3f}")

# Show what happens at L9470 (CLOSE of FID=e1...)
print("\n=== CLOSE at L9470 ===")
for pk in paquetes:
    if 9465 <= pk.linea <= 9475:
        print(f"  L{pk.linea:4d} {pk.comando:16s} FID={str(pk.file_id or ''):30s} t={pk.timestamp:.3f}")

# Show last packets
print("\n=== Last packets ===")
for pk in paquetes[-5:]:
    print(f"  L{pk.linea:4d} {pk.comando:16s} FID={str(pk.file_id or ''):30s} t={pk.timestamp:.3f}")

# Check: does FID=dd... ever appear again?
fid_dd = 'dd0000000000000009000000ffffffff'
count_dd = sum(1 for pk in paquetes if pk.file_id == fid_dd)
print(f"\nFID=dd... appears {count_dd} times")
for pk in paquetes:
    if pk.file_id == fid_dd:
        print(f"  L{pk.linea:4d} {pk.comando:16s} t={pk.timestamp:.3f}")

# Check: what's the first CREATE with a FileID that has a CLOSE?
print("\n=== First 20 CREATEs with their CLOSE status ===")
creates = [(pk, None) for pk in paquetes if pk.comando == 'CREATE' and pk.file_id]
for c, _ in creates[:20]:
    close_line = None
    for pk in paquetes:
        if pk.comando == 'CLOSE' and pk.file_id == c.file_id:
            close_line = pk.linea
            break
    has_close = "YES" if close_line else "NO"
    print(f"  L{c.linea:4d} FID={c.file_id:30s} -> CLOSE L{close_line} [{has_close}]")
