#!/usr/bin/env python3
"""Debug v4 - check if L37 CREATE has error."""
import sys
sys.path.insert(0, 'src')
from analizador_smb2_v4 import leer_csv

paquetes = leer_csv('Trazas/Traza_user_5.csv')

# Show L37 in detail
for pk in paquetes:
    if pk.linea == 37:
        print(f"L{pk.linea}: comando={pk.comando} FID={pk.file_id} t={pk.timestamp}")
        print(f"  create_options={pk.create_options} info_class={pk.info_class}")
        print(f"  tiene_error={pk.tiene_error} file_path={pk.file_path}")
        print(f"  tree_id={pk.tree_id}")

# Show the raw CSV line for L37
with open('Trazas/Traza_user_5.csv', 'r', encoding='utf-8-sig') as f:
    for i, line in enumerate(f, 1):
        if i == 37:
            print(f"\nRaw CSV L37: {line.strip()}")
            parts = line.strip().split(',')
            for j, p in enumerate(parts):
                print(f"  [{j}] = '{p}'")
            break
