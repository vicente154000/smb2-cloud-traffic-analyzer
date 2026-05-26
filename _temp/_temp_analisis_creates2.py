#!/usr/bin/env python3
"""Analisis mas profundo de CREATEs sin CLOSE en salidaSemana.txt."""
import sys
sys.path.insert(0, 'src')
from collections import defaultdict

from analizador_smb2_v4 import leer_csv
print("Cargando salidaSemana.txt...")
paquetes = leer_csv('Trazas/salidaSemana.txt')

# Por FileID: info detallada
fids_info = defaultdict(lambda: {
    'comandos': set(), 'num_paquetes': 0,
    'tree_ids': set(), 'timestamps': [],
    'primer_create': None, 'ultimo_paquete': None
})

for p in paquetes:
    if p.file_id:
        info = fids_info[p.file_id]
        info['comandos'].add(p.comando)
        info['num_paquetes'] += 1
        if p.tree_id is not None:
            info['tree_ids'].add(p.tree_id)
        info['timestamps'].append(p.timestamp)
        if p.comando == 'CREATE' and info['primer_create'] is None:
            info['primer_create'] = p.timestamp
        info['ultimo_paquete'] = p.timestamp

# Separar los que tienen CREATE pero no CLOSE
sin_close = {fid: info for fid, info in fids_info.items() 
             if 'CREATE' in info['comandos'] and 'CLOSE' not in info['comandos']}

print(f"\nTotal FileIDs con CREATE sin CLOSE: {len(sin_close)}")

# 1. Distribucion temporal: cuando aparecen estos FileIDs?
print(f"\n--- Distribucion temporal ---")
rangos = defaultdict(int)
for fid, info in sin_close.items():
    if info['primer_create']:
        hora = info['primer_create'] / 3600  # convertir a horas
        if hora < 24:
            rangos['Dia 1 (0-24h)'] += 1
        elif hora < 48:
            rangos['Dia 2 (24-48h)'] += 1
        elif hora < 72:
            rangos['Dia 3 (48-72h)'] += 1
        elif hora < 96:
            rangos['Dia 4 (72-96h)'] += 1
        elif hora < 120:
            rangos['Dia 5 (96-120h)'] += 1
        elif hora < 144:
            rangos['Dia 6 (120-144h)'] += 1
        else:
            rangos['Dia 7+ (144h+)'] += 1

for r, c in sorted(rangos.items()):
    print(f"  {r}: {c} FileIDs")

# 2. Distribucion por TreeID
print(f"\n--- Top 10 TreeIDs con mas FileIDs sin CLOSE ---")
tree_counts = defaultdict(int)
for fid, info in sin_close.items():
    for tid in info['tree_ids']:
        tree_counts[tid] += 1
for tid, count in sorted(tree_counts.items(), key=lambda x: -x[1])[:10]:
    print(f"  TreeID {tid}: {count} FileIDs sin CLOSE")

# 3. Los que tienen MAS paquetes (los mas problematicos)
print(f"\n--- Top 20 FileIDs sin CLOSE con MAS paquetes ---")
top = sorted(sin_close.items(), key=lambda x: -x[1]['num_paquetes'])[:20]
for fid, info in top:
    cmds = '+'.join(sorted(info['comandos'] - {'CREATE'})) if len(info['comandos'])>1 else 'SOLO_CREATE'
    duracion = info['ultimo_paquete'] - info['primer_create'] if info['primer_create'] else 0
    print(f"  {fid[:30]}... | paqs:{info['num_paquetes']:5d} | cmds:{cmds:30s} | duracion:{duracion:8.2f}s | tree:{list(info['tree_ids'])[:2]}")

# 4. Cuantos de estos sin_close tienen SOLO CREATE (0 actividad)?
solo_create = sum(1 for info in sin_close.values() if len(info['comandos']) == 1)
con_lectura = sum(1 for info in sin_close.values() if 'READ' in info['comandos'])
con_escritura = sum(1 for info in sin_close.values() if 'WRITE' in info['comandos'])
con_setinfo = sum(1 for info in sin_close.values() if 'SET_INFO' in info['comandos'])
print(f"\n--- Actividad de los FileIDs sin CLOSE ---")
print(f"  Solo CREATE (sin actividad): {solo_create}")
print(f"  Con READ: {con_lectura}")
print(f"  Con WRITE: {con_escritura}")
print(f"  Con SET_INFO: {con_setinfo}")

# 5. Cuantos estan al FINAL de la traza (ultimo 1% del tiempo)?
if paquetes:
    t_max = max(p.timestamp for p in paquetes if p.file_id)
    t_min = min(p.timestamp for p in paquetes if p.file_id)
    rango_total = t_max - t_min
    final_traza = t_max - (rango_total * 0.01)  # ultimo 1%
    
    al_final = sum(1 for info in sin_close.values() 
                   if info['primer_create'] and info['primer_create'] >= final_traza)
    print(f"\nRango temporal total: {rango_total:.0f}s ({rango_total/3600:.1f}h)")
    print(f"FileIDs sin CLOSE que empiezan en el ultimo 1%: {al_final}")

# 6. Cuantos estan al INICIO de la traza (primer 1%)?
    inicio_traza = t_min + (rango_total * 0.01)
    al_inicio = sum(1 for info in sin_close.values()
                    if info['ultimo_paquete'] and info['ultimo_paquete'] <= inicio_traza)
    print(f"FileIDs sin CLOSE que terminan en el primer 1%: {al_inicio}")
