#!/usr/bin/env python3
"""Debug: analizar las operaciones compuestas de v4 con salidaSemana.txt"""
import sys
sys.path.insert(0, 'src')

from analizador_smb2_v4 import (
    leer_csv, agrupar_por_operacion_v4, clasificar_operacion_compuesta,
    _es_copiar_carpeta, _es_comprimir_archivo, _es_comprimir_carpeta,
    _es_modificar_archivo_editor, _es_subir_carpeta, _es_bajar_carpeta,
    _es_operacion_compleja
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

# Analizar las primeras 30 compuestas
for i, op in enumerate(compuestas[:30]):
    comandos = [p.comando for p in op.paquetes]
    fileids = set(p.file_id for p in op.paquetes if p.file_id)
    creates = [p for p in op.paquetes if p.comando == 'CREATE']
    info_classes = set()
    for p in op.paquetes:
        if p.info_class is not None:
            info_classes.add(p.info_class)
    
    print(f"--- Compuesta {i+1} ---")
    print(f"  FileIDs: {len(fileids)}, Paquetes: {len(op.paquetes)}")
    print(f"  Creates: {len(creates)}")
    print(f"  Comandos: {sorted(set(comandos))}")
    print(f"  InfoClasses: {info_classes}")
    print(f"  Lineas: {op.linea_inicio}--{op.linea_fin}")
    
    # Ver cada detector
    print(f"  copiar_carpeta={_es_copiar_carpeta(op.paquetes, comandos, fileids, creates)}")
    print(f"  comprimir_archivo={_es_comprimir_archivo(op.paquetes, comandos, fileids, creates)}")
    print(f"  comprimir_carpeta={_es_comprimir_carpeta(op.paquetes, comandos, fileids, creates)}")
    print(f"  modificar_archivo={_es_modificar_archivo_editor(op.paquetes, comandos, fileids, creates)}")
    print(f"  subir_carpeta={_es_subir_carpeta(op.paquetes, comandos, fileids, creates)}")
    print(f"  bajar_carpeta={_es_bajar_carpeta(op.paquetes, comandos, fileids, creates)}")
    print(f"  operacion_compleja={_es_operacion_compleja(op.paquetes, comandos, fileids, creates)}")
    
    tipo = clasificar_operacion_compuesta(op)
    print(f"  CLASIFICACION: {tipo}")
    print()
