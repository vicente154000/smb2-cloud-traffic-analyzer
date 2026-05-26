#!/usr/bin/env python3
"""Contar CREATEs totales y FileIDs sin CLOSE."""
import sys
sys.path.insert(0, 'src')
from collections import defaultdict
from analizador_smb2_v4 import leer_csv

import time
start = time.time()

print("Cargando salidaSemana.txt...")
sys.stdout.flush()
paquetes = leer_csv('Trazas/salidaSemana.txt')
print(f"Total paquetes: {len(paquetes)} ({time.time()-start:.1f}s)")
sys.stdout.flush()

total_creates = 0
fids_con_create = set()
fids_con_close = set()

for i, p in enumerate(paquetes):
    if p.file_id:
        if p.comando == 'CREATE':
            total_creates += 1
            fids_con_create.add(p.file_id)
        elif p.comando == 'CLOSE':
            fids_con_close.add(p.file_id)
    if i > 0 and i % 5000000 == 0:
        print(f"  Procesados {i} paquetes... ({time.time()-start:.1f}s)")
        sys.stdout.flush()

print(f"Procesados todos los paquetes ({time.time()-start:.1f}s)")
sys.stdout.flush()

fids_sin_close = fids_con_create - fids_con_close

print(f"\n=== RESULTADOS ===")
print(f"Total paquetes CREATE: {total_creates}")
print(f"FileIDs unicos con CREATE: {len(fids_con_create)}")
print(f"FileIDs unicos con CLOSE: {len(fids_con_close)}")
print(f"FileIDs con CREATE pero SIN CLOSE: {len(fids_sin_close)}")
print(f"% FileIDs sin CLOSE: {len(fids_sin_close)/len(fids_con_create)*100:.2f}%")
print(f"Tiempo total: {time.time()-start:.1f}s")
sys.stdout.flush()
