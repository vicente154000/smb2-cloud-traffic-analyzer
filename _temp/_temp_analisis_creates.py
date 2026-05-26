#!/usr/bin/env python3
"""Analisis de CREATEs sin CLOSE en ambas trazas."""
import sys
sys.path.insert(0, 'src')
from collections import defaultdict

def analizar(ruta, nombre):
    from analizador_smb2_v4 import leer_csv
    print(f"\n{'='*60}")
    print(f"ANALISIS: {nombre}")
    print(f"{'='*60}")
    
    paquetes = leer_csv(ruta)
    
    # Por cada FileID, guardar: comandos que tiene, si tiene CREATE, si tiene CLOSE
    fids_info = defaultdict(lambda: {'comandos': set(), 'tiene_create': False, 'tiene_close': False, 'num_paquetes': 0})
    
    for p in paquetes:
        if p.file_id:
            fids_info[p.file_id]['comandos'].add(p.comando)
            fids_info[p.file_id]['num_paquetes'] += 1
            if p.comando == 'CREATE':
                fids_info[p.file_id]['tiene_create'] = True
            elif p.comando == 'CLOSE':
                fids_info[p.file_id]['tiene_close'] = True
    
    total_fids = len(fids_info)
    con_create = sum(1 for v in fids_info.values() if v['tiene_create'])
    con_close = sum(1 for v in fids_info.values() if v['tiene_close'])
    create_sin_close = sum(1 for v in fids_info.values() if v['tiene_create'] and not v['tiene_close'])
    close_sin_create = sum(1 for v in fids_info.values() if v['tiene_close'] and not v['tiene_create'])
    
    print(f"\nTotal FileIDs unicos: {total_fids}")
    print(f"FileIDs con CREATE: {con_create}")
    print(f"FileIDs con CLOSE: {con_close}")
    print(f"FileIDs con CREATE pero SIN CLOSE: {create_sin_close}")
    print(f"FileIDs con CLOSE pero SIN CREATE: {close_sin_create}")
    
    # Analizar los CREATEs sin CLOSE: que comandos tienen?
    print(f"\n--- Analisis de {create_sin_close} FileIDs con CREATE sin CLOSE ---")
    patrones = defaultdict(int)
    for fid, info in fids_info.items():
        if info['tiene_create'] and not info['tiene_close']:
            otros = info['comandos'] - {'CREATE'}
            clave = '+'.join(sorted(otros)) if otros else 'SOLO_CREATE'
            patrones[clave] += 1
    
    print("Distribucion de comandos en esos FileIDs:")
    for patron, count in sorted(patrones.items(), key=lambda x: -x[1]):
        print(f"  {patron}: {count} FileIDs")
    
    # Cuantos paquetes totales se "pierden" por descartar estos CREATEs?
    paquetes_perdidos = sum(info['num_paquetes'] for fid, info in fids_info.items() 
                           if info['tiene_create'] and not info['tiene_close'])
    total_paquetes_con_fid = sum(info['num_paquetes'] for info in fids_info.values())
    print(f"\nPaquetes totales con FileID: {total_paquetes_con_fid}")
    print(f"Paquetes en FileIDs sin CLOSE: {paquetes_perdidos} ({paquetes_perdidos/total_paquetes_con_fid*100:.2f}%)")
    
    # Top 10 FileIDs sin CLOSE con mas paquetes
    print(f"\nTop 10 FileIDs sin CLOSE con mas paquetes:")
    top = [(fid, info) for fid, info in fids_info.items() 
           if info['tiene_create'] and not info['tiene_close']]
    top.sort(key=lambda x: -x[1]['num_paquetes'])
    for fid, info in top[:10]:
        print(f"  {fid[:20]}... | paqs: {info['num_paquetes']:4d} | cmds: {sorted(info['comandos'])}")

analizar('Trazas/Traza_user_5.csv', 'Traza_user_5.csv')
analizar('Trazas/salidaSemana.txt', 'salidaSemana.txt')
