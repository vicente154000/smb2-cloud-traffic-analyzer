#!/usr/bin/env python3
"""Debug script to analyze v4 grouping behavior."""
import sys
sys.path.insert(0, 'src')
from analizador_smb2_v4 import leer_csv, agrupar_por_operacion_v4

paquetes = leer_csv('Trazas/Traza_user_5.csv')
print(f"Total paquetes: {len(paquetes)}")

# Find first CREATE and its CLOSE
first_create = None
for pk in paquetes:
    if pk.comando == 'CREATE':
        first_create = pk
        break

print(f"First CREATE: L{first_create.linea} FID={first_create.file_id} t={first_create.timestamp} path={first_create.file_path}")

# Find CLOSE for that FID
for pk in paquetes:
    if pk.comando == 'CLOSE' and pk.file_id == first_create.file_id:
        print(f"CLOSE for that FID: L{pk.linea} t={pk.timestamp}")

# Show first 10 CREATEs with their CLOSE lines
creates = [pk for pk in paquetes if pk.comando == 'CREATE']
print(f"\nTotal CREATEs: {len(creates)}")
print("First 10 CREATEs:")
for c in creates[:10]:
    close_line = None
    for pk in paquetes:
        if pk.comando == 'CLOSE' and pk.file_id == c.file_id:
            close_line = pk.linea
            break
    print(f"  CREATE L{c.linea} FID={c.file_id} -> CLOSE L{close_line}")

# Now group and show details
ops = agrupar_por_operacion_v4(paquetes)
print(f"\nTotal operations: {len(ops)}")
for i, op in enumerate(ops):
    print(f"[{i+1}] simple={op.es_simple} fids={op.num_file_ids} pkts={op.num_paquetes} lines=[{op.linea_inicio}--{op.linea_fin}]")
    if op.num_file_ids <= 5:
        print(f"     FIDs: {op.file_ids}")
    if op.num_file_ids > 100:
        # Show first 5 and last 5 FIDs
        fid_list = sorted(list(op.file_ids))
        print(f"     FIDs: {fid_list[:5]} ... {fid_list[-5:]}")
