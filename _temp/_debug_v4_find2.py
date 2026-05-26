#!/usr/bin/env python3
"""Ver donde estan los QUERY_DIRECTORY en v4 - version fresca"""
import sys
import importlib
sys.path.insert(0, 'src')

# Forzar recarga
import analizador_smb2_v4
importlib.reload(analizador_smb2_v4)

from analizador_smb2_v4 import leer_csv, agrupar_por_operacion_v4

print("Leyendo traza...")
paquetes = leer_csv('Trazas/salidaSemana.txt')
print(f"Total paquetes: {len(paquetes)}")

print("Agrupando...")
ops = agrupar_por_operacion_v4(paquetes)
print(f"Total operaciones: {len(ops)}")

# Contar FINDs en operaciones vs fuera
find_en_ops = 0
for op in ops:
    find_count = sum(1 for p in op.paquetes if p.comando == 'QUERY_DIRECTORY')
    if find_count > 0:
        if op.es_simple:
            print(f"  FIND en SIMPLE: {find_count} FINDs, FileIDs={op.num_file_ids}, Lineas={op.linea_inicio}--{op.linea_fin}")
        else:
            print(f"  FIND en COMPUESTA: {find_count} FINDs, FileIDs={op.num_file_ids}, Lineas={op.linea_inicio}--{op.linea_fin}")
        find_en_ops += find_count

# Contar FINDs totales
total_find = sum(1 for p in paquetes if p.comando == 'QUERY_DIRECTORY')
find_fuera = total_find - find_en_ops

print()
print(f"Total FINDs en traza: {total_find}")
print(f"FINDs dentro de operaciones: {find_en_ops}")
print(f"FINDs fuera de operaciones: {find_fuera}")
print(f"Operaciones con FIND: {sum(1 for op in ops if any(p.comando == 'QUERY_DIRECTORY' for p in op.paquetes))}")
