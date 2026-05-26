#!/usr/bin/env python3
"""Debug v4: analizar compuestas con detalle de creates y secuencia"""
import sys
sys.path.insert(0, 'src')

from analizador_smb2_v4 import (
    leer_csv, agrupar_por_operacion_v4, _es_directorio
)

print("Leyendo traza...")
paquetes = leer_csv('Trazas/salidaSemana.txt')
print(f"Total paquetes: {len(paquetes)}")

print("Agrupando...")
ops = agrupar_por_operacion_v4(paquetes)
print(f"Total operaciones: {len(ops)}")

compuestas = [op for op in ops if not op.es_simple]
print(f"Total compuestas: {len(compuestas)}")
print()

# Contadores
stats = {
    'solo_read': 0,
    'read_write': 0,
    'read_write_setinfo': 0,
    'solo_write': 0,
    'write_setinfo': 0,
    'otros': 0
}

for i, op in enumerate(compuestas):
    comandos = [p.comando for p in op.paquetes]
    fileids = set(p.file_id for p in op.paquetes if p.file_id)
    creates = [p for p in op.paquetes if p.comando == 'CREATE']
    
    cmd_set = set(comandos)
    has_read = 'READ' in cmd_set
    has_write = 'WRITE' in cmd_set
    has_setinfo = 'SET_INFO' in cmd_set
    has_find = 'QUERY_DIRECTORY' in cmd_set
    has_ioctl = 'IOCTL' in cmd_set
    
    # Tipo de primer CREATE
    first_create = creates[0] if creates else None
    es_dir = _es_directorio(first_create.create_options) if first_create and first_create.create_options is not None else None
    
    # Determinar patron
    if has_read and not has_write and not has_setinfo:
        stats['solo_read'] += 1
        patron = "SOLO READ"
    elif has_read and has_write and not has_setinfo:
        stats['read_write'] += 1
        patron = "READ+WRITE"
    elif has_read and has_write and has_setinfo:
        stats['read_write_setinfo'] += 1
        patron = "READ+WRITE+SET_INFO"
    elif not has_read and has_write and not has_setinfo:
        stats['solo_write'] += 1
        patron = "SOLO WRITE"
    elif not has_read and has_write and has_setinfo:
        stats['write_setinfo'] += 1
        patron = "WRITE+SET_INFO"
    else:
        stats['otros'] += 1
        patron = f"OTRO: {sorted(cmd_set)}"
    
    if i < 50:
        print(f"#{i+1:3d} | {patron:25s} | FileIDs={len(fileids):4d} | Creates={len(creates):3d} | Paqs={len(op.paquetes):4d} | "
              f"FIND={has_find} | IOCTL={has_ioctl} | "
              f"1erCREATE_dir={es_dir} | Lineas={op.linea_inicio}--{op.linea_fin}")

print()
print("=== ESTADISTICAS GLOBALES ===")
for k, v in stats.items():
    print(f"  {k}: {v} ({v*100//len(compuestas)}%)")
print(f"  TOTAL: {len(compuestas)}")
