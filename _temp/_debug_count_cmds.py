#!/usr/bin/env python3
"""Contar comandos en salidaSemana.txt"""
import sys
sys.path.insert(0, 'src')
from analizador_smb2_v4 import leer_csv

paquetes = leer_csv('Trazas/salidaSemana.txt')

total = len(paquetes)
query_dir = sum(1 for p in paquetes if p.comando == 'QUERY_DIRECTORY')
query_info = sum(1 for p in paquetes if p.comando == 'QUERY_INFO')
creates = sum(1 for p in paquetes if p.comando == 'CREATE')
closes = sum(1 for p in paquetes if p.comando == 'CLOSE')
reads = sum(1 for p in paquetes if p.comando == 'READ')
writes = sum(1 for p in paquetes if p.comando == 'WRITE')
setinfos = sum(1 for p in paquetes if p.comando == 'SET_INFO')
ioctls = sum(1 for p in paquetes if p.comando == 'IOCTL')

print(f'Total paquetes: {total}')
print(f'CREATE: {creates}')
print(f'CLOSE: {closes}')
print(f'READ: {reads}')
print(f'WRITE: {writes}')
print(f'SET_INFO: {setinfos}')
print(f'QUERY_DIRECTORY (FIND): {query_dir}')
print(f'QUERY_INFO: {query_info}')
print(f'IOCTL: {ioctls}')
