#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
clasificador_segundo_nivel.py — Fusion de operaciones atomicas en complejas
===========================================================================
TFG: Caracterizacion tecnica del protocolo SMB2 mediante analisis de trafico

Este modulo implementa un clasificador de segundo nivel que toma las
operaciones atomicas (1 FileID) producidas por v2 y las fusiona en
operaciones complejas multi-FileID cuando detecta patrones conocidos.

Estrategia:
  1. Recibe la lista de operaciones atomicas de v2 (ordenadas por timestamp).
  2. Busca patrones de operaciones consecutivas que, juntas, forman una
     operacion de usuario de nivel superior (COMPRIMIR, COPIAR, MODIFICAR...).
  3. Fusiona las operaciones atomicas que coinciden con un patron en una
     sola operacion compleja.

Patrones detectados:
  - COMPRIMIR ARCHIVO: BAJAR ARCHIVO + SUBIR ARCHIVO (consecutivos, <2s)
  - MODIFICAR ARCHIVO: BAJAR ARCHIVO + SUBIR ARCHIVO (mismo file_path)
  - SUBIR CARPETA: (SUBIR ARCHIVO)*N consecutivos, misma carpeta
  - BAJAR CARPETA: (BAJAR ARCHIVO)*N consecutivos, misma carpeta
  - COPIAR CARPETA: LISTAR DIRECTORIO + (BAJAR+SUBIR)*N
  - COMPRIMIR CARPETA: LISTAR DIRECTORIO + (BAJAR)*N + SUBIR ARCHIVO
"""

import sys
import os
from collections import defaultdict

# Umbral temporal para considerar operaciones como parte de la misma accion
UMBRAL_TEMPORAL_SEG = 2.0


# ──────────────────────────────────────────────────────────────────────
# FUNCIONES AUXILIARES
# ──────────────────────────────────────────────────────────────────────

def _extraer_directorio(file_path):
    """Extrae el directorio de una ruta de archivo."""
    if not file_path:
        return None
    idx = file_path.rfind("/")
    if idx == -1:
        idx = file_path.rfind("\\")
    if idx == -1:
        return None
    return file_path[:idx]


def _extraer_nombre(file_path):
    """Extrae el nombre del archivo de una ruta."""
    if not file_path:
        return None
    idx = file_path.rfind("/")
    if idx == -1:
        idx = file_path.rfind("\\")
    if idx == -1:
        return file_path
    return file_path[idx + 1:]


def _misma_carpeta(op1, op2):
    """Comprueba si dos operaciones operan sobre archivos en la misma carpeta."""
    d1 = _extraer_directorio(op1.archivo)
    d2 = _extraer_directorio(op2.archivo)
    return d1 is not None and d2 is not None and d1 == d2


def _mismo_archivo(op1, op2):
    """Comprueba si dos operaciones operan sobre el mismo archivo."""
    return (op1.archivo and op2.archivo and op1.archivo == op2.archivo)


def _cerca_en_tiempo(op1, op2, umbral=UMBRAL_TEMPORAL_SEG):
    """Comprueba si dos operaciones estan cerca en el tiempo."""
    if not op1 or not op2:
        return False
    diff = abs(op2.timestamp_inicio - op1.timestamp_fin)
    return diff <= umbral


def _operaciones_consecutivas(ops, inicio, n):
    """Devuelve True si hay al menos n operaciones desde 'inicio'."""
    return inicio + n <= len(ops)


def _rango_temporal(ops):
    """Calcula el rango temporal de una lista de operaciones."""
    if not ops:
        return (0, 0)
    t_min = min(op.timestamp_inicio for op in ops)
    t_max = max(op.timestamp_fin for op in ops)
    return (t_min, t_max)


# ──────────────────────────────────────────────────────────────────────
# CLASIFICADOR DE SEGUNDO NIVEL
# ──────────────────────────────────────────────────────────────────────

def clasificar_segundo_nivel(operaciones_atomicas):
    """
    Toma operaciones atomicas (1 FileID) y las fusiona en operaciones
    complejas multi-FileID cuando detecta patrones.

    Args:
        operaciones_atomicas: lista de objetos Operacion de v2,
                             ordenados por timestamp

    Returns:
        lista de objetos Operacion (algunos fusionados, otros atomicos)
    """
    if not operaciones_atomicas:
        return []

    ops = list(operaciones_atomicas)  # copia
    fusionadas = []  # resultado: operaciones finales
    usadas = set()   # indices de ops ya fusionadas
    i = 0

    while i < len(ops):
        if i in usadas:
            i += 1
            continue

        op = ops[i]
        fusionada = None

        # --- Patron 1: COMPRIMIR ARCHIVO ---
        # BAJAR ARCHIVO + SUBIR ARCHIVO (consecutivos, cerca en tiempo,
        # archivos diferentes en la misma carpeta)
        if (op.tipo == "BAJAR ARCHIVO"
                and _operaciones_consecutivas(ops, i + 1, 1)
                and (i + 1) not in usadas
                and ops[i + 1].tipo == "SUBIR ARCHIVO"
                and _cerca_en_tiempo(op, ops[i + 1])
                and not _mismo_archivo(op, ops[i + 1])):
            # Fusionar: COMPRIMIR ARCHIVO
            fusionada = _fusionar_ops([op, ops[i + 1]], "COMPRIMIR ARCHIVO")
            usadas.add(i)
            usadas.add(i + 1)
            i += 2
            # Ver si hay mas SUBIR ARCHIVO (comprimir varios archivos)
            while (i < len(ops) and i not in usadas
                   and ops[i].tipo == "SUBIR ARCHIVO"
                   and _cerca_en_tiempo(fusionada, ops[i])):
                fusionada = _fusionar_ops([fusionada, ops[i]],
                                          "COMPRIMIR ARCHIVO")
                usadas.add(i)
                i += 1

        # --- Patron 2: MODIFICAR ARCHIVO (editor) ---
        # BAJAR ARCHIVO + SUBIR ARCHIVO (mismo archivo, cerca en tiempo)
        elif (op.tipo == "BAJAR ARCHIVO"
              and _operaciones_consecutivas(ops, i + 1, 1)
              and (i + 1) not in usadas
              and ops[i + 1].tipo == "SUBIR ARCHIVO"
              and _cerca_en_tiempo(op, ops[i + 1])
              and _mismo_archivo(op, ops[i + 1])):
            fusionada = _fusionar_ops([op, ops[i + 1]],
                                      "MODIFICAR ARCHIVO (editor)")
            usadas.add(i)
            usadas.add(i + 1)
            i += 2

        # --- Patron 3: SUBIR CARPETA ---
        # Varios SUBIR ARCHIVO consecutivos, misma carpeta
        elif op.tipo == "SUBIR ARCHIVO":
            grupo = [op]
            usadas.add(i)
            j = i + 1
            while (j < len(ops) and j not in usadas
                   and ops[j].tipo == "SUBIR ARCHIVO"
                   and _misma_carpeta(op, ops[j])
                   and _cerca_en_tiempo(ops[j - 1], ops[j])):
                grupo.append(ops[j])
                usadas.add(j)
                j += 1
            if len(grupo) >= 2:
                fusionada = _fusionar_ops(grupo, "SUBIR CARPETA")
                i = j
            else:
                # Solo 1 SUBIR ARCHIVO -> mantener como atomico
                usadas.discard(i)
                fusionada = None
                i += 1

        # --- Patron 4: BAJAR CARPETA ---
        # Varios BAJAR ARCHIVO consecutivos, misma carpeta
        elif op.tipo == "BAJAR ARCHIVO":
            grupo = [op]
            usadas.add(i)
            j = i + 1
            while (j < len(ops) and j not in usadas
                   and ops[j].tipo == "BAJAR ARCHIVO"
                   and _misma_carpeta(op, ops[j])
                   and _cerca_en_tiempo(ops[j - 1], ops[j])):
                grupo.append(ops[j])
                usadas.add(j)
                j += 1
            if len(grupo) >= 2:
                fusionada = _fusionar_ops(grupo, "BAJAR CARPETA")
                i = j
            else:
                usadas.discard(i)
                fusionada = None
                i += 1

        # --- Patron 5: COPIAR CARPETA ---
        # LISTAR DIRECTORIO + (BAJAR ARCHIVO + SUBIR ARCHIVO)*N
        elif (op.tipo == "LISTAR DIRECTORIO"
              and _operaciones_consecutivas(ops, i + 1, 2)
              and (i + 1) not in usadas
              and (i + 2) not in usadas
              and ops[i + 1].tipo == "BAJAR ARCHIVO"
              and ops[i + 2].tipo == "SUBIR ARCHIVO"
              and _cerca_en_tiempo(op, ops[i + 1])):
            grupo = [op]
            usadas.add(i)
            j = i + 1
            # Consumir pares BAJAR+SUBIR
            while (j + 1 < len(ops) and j not in usadas
                   and (j + 1) not in usadas
                   and ops[j].tipo == "BAJAR ARCHIVO"
                   and ops[j + 1].tipo == "SUBIR ARCHIVO"
                   and _cerca_en_tiempo(ops[j], ops[j + 1])):
                grupo.append(ops[j])
                grupo.append(ops[j + 1])
                usadas.add(j)
                usadas.add(j + 1)
                j += 2
            if len(grupo) >= 3:  # LISTAR + al menos 1 par
                fusionada = _fusionar_ops(grupo, "COPIAR CARPETA")
                i = j
            else:
                # No es COPIAR CARPETA, restaurar
                for idx in range(i, j):
                    usadas.discard(idx)
                fusionada = None
                i += 1

        # --- Patron 6: COMPRIMIR CARPETA ---
        # LISTAR DIRECTORIO + (BAJAR ARCHIVO)*N + SUBIR ARCHIVO
        elif (op.tipo == "LISTAR DIRECTORIO"
              and _operaciones_consecutivas(ops, i + 1, 2)
              and (i + 1) not in usadas
              and ops[i + 1].tipo == "BAJAR ARCHIVO"):
            grupo = [op]
            usadas.add(i)
            j = i + 1
            # Consumir BAJAR ARCHIVO*N
            while (j < len(ops) and j not in usadas
                   and ops[j].tipo == "BAJAR ARCHIVO"
                   and _cerca_en_tiempo(ops[j - 1] if j > i else op, ops[j])):
                grupo.append(ops[j])
                usadas.add(j)
                j += 1
            # Consumir SUBIR ARCHIVO final
            if (j < len(ops) and j not in usadas
                    and ops[j].tipo == "SUBIR ARCHIVO"
                    and _cerca_en_tiempo(ops[j - 1], ops[j])):
                grupo.append(ops[j])
                usadas.add(j)
                j += 1
                if len(grupo) >= 3:  # LISTAR + al menos 1 BAJAR + 1 SUBIR
                    fusionada = _fusionar_ops(grupo, "COMPRIMIR CARPETA")
                    i = j
                else:
                    for idx in range(i, j):
                        usadas.discard(idx)
                    fusionada = None
                    i += 1
            else:
                for idx in range(i, j):
                    usadas.discard(idx)
                fusionada = None
                i += 1

        if fusionada is not None:
            fusionadas.append(fusionada)
        else:
            # Operacion atomica no fusionada
            if i not in usadas:
                fusionadas.append(op)
                i += 1

    return fusionadas


def _fusionar_ops(ops_list, nuevo_tipo):
    """
    Fusiona varias operaciones atomicas en una sola operacion compleja.
    Crea un nuevo objeto Operacion con todos los paquetes de las originales.
    """
    # Importamos Operacion de v2
    from analizador_smb2_v2 import Operacion

    fusionada = Operacion()
    for op in ops_list:
        for pkt in op.paquetes:
            fusionada.anyadir(pkt)
    fusionada.tipo = nuevo_tipo
    return fusionada


# ──────────────────────────────────────────────────────────────────────
# MAIN (para pruebas independientes)
# ──────────────────────────────────────────────────────────────────────

def main():
    """Ejecuta el pipeline completo: v2 + segundo nivel."""
    if len(sys.argv) < 2:
        print("Uso: python src/clasificador_segundo_nivel.py <csv> [--resumen]")
        sys.exit(1)

    ruta_csv = sys.argv[1]
    solo_resumen = "--resumen" in sys.argv

    if not os.path.exists(ruta_csv):
        print(f"Error: no se encuentra {ruta_csv}")
        sys.exit(1)

    print(f"\nAnalizando {ruta_csv}...")

    # Paso 1: v2 (operaciones atomicas)
    from analizador_smb2_v2 import leer_csv, agrupar_por_operacion, clasificar_operacion

    paquetes = leer_csv(ruta_csv)
    print(f"  Paquetes SMB2 leidos: {len(paquetes)}")

    operaciones_v2 = agrupar_por_operacion(paquetes)
    print(f"  Operaciones atomicas (v2): {len(operaciones_v2)}")

    # Clasificar cada operacion atomica
    for op in operaciones_v2:
        op.tipo = clasificar_operacion(op)

    # Paso 2: Segundo nivel
    operaciones_complejas = clasificar_segundo_nivel(operaciones_v2)
    print(f"  Operaciones tras segundo nivel: {len(operaciones_complejas)}")

    # Reporte
    if solo_resumen:
        _generar_resumen(operaciones_complejas)
    else:
        _generar_reporte(operaciones_complejas)


def _generar_resumen(operaciones):
    """Genera resumen de tipos de operacion."""
    conteo = defaultdict(int)
    for op in operaciones:
        conteo[op.tipo] += 1

    print(f"\n{'=' * 60}")
    print(f"  RESUMEN DE OPERACIONES (v2 + segundo nivel)")
    print(f"{'=' * 60}")
    print(f"\n  Total operaciones: {len(operaciones)}\n")
    print(f"  {'Tipo de operacion':35s} {'Cantidad':>8s} {'%':>8s}")
    print(f"  {'-' * 35} {'-' * 8} {'-' * 8}")
    for tipo, cant in sorted(conteo.items(), key=lambda x: -x[1]):
        pct = cant / len(operaciones) * 100
        print(f"  {tipo:35s} {cant:8d} {pct:7.1f}%")


def _generar_reporte(operaciones):
    """Genera reporte detallado de operaciones."""
    print(f"\n{'=' * 60}")
    print(f"  REPORTE DE OPERACIONES (v2 + segundo nivel)")
    print(f"{'=' * 60}")
    print(f"\nTotal operaciones: {len(operaciones)}\n")

    for i, op in enumerate(operaciones, 1):
        file_ids = len(op.file_ids)
        print(f"  {i:4d}. [{op.tipo}] "
              f"{op.timestamp_inicio:.3f}-{op.timestamp_fin:.3f} "
              f"({op.num_paquetes} paqs, {file_ids} FileIDs)"
              f"{'  ' + op.archivo if op.archivo else ''}")

    _generar_resumen(operaciones)


if __name__ == "__main__":
    main()
