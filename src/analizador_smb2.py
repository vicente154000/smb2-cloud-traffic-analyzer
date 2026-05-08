#!/usr/bin/env python3
"""
analizador_smb2.py — Analizador de operaciones de usuario en trazas SMB2
===========================================================================
TFG: Caracterizacion tecnica del protocolo SMB2 mediante analisis de trafico

Este script lee un CSV exportado de Wireshark con trazas SMB2, agrupa los
paquetes por operacion (mismo FileID y cercania temporal), y clasifica cada
grupo en una operacion de usuario.

Uso:
    python analizador_smb2.py Trazas/Traza_user_5.csv
"""

import csv
import sys
import os
from collections import defaultdict


# ──────────────────────────────────────────────────────────────────────
# CONSTANTES
# ──────────────────────────────────────────────────────────────────────

# InfoClass de SET_INFO (columna 16 del CSV)
INFO_CLASS_BORRAR   = 0x0D  # FileDispositionInformation -> BORRAR
INFO_CLASS_RENOMBRAR = 0x0A # FileRenameInformation -> RENOMBRAR

# CreateOptions de CREATE (columna 15)
CREATE_OPTIONS_DIRECTORIO = 0x01  # FILE_DIRECTORY_FILE -> es carpeta

# Si entre dos paquetes del mismo FileID pasan mas de X segundos,
# los separamos en operaciones distintas
UMBRAL_TEMPORAL_SEG = 2.0

# Comandos de "ruido" del SO que ignoramos
RUIDO_OS = {"NEGOTIATE", "SESSION_SETUP", "LOGOFF", "TREE_CONNECT",
            "TREE_DISCONNECT", "ECHO", "CANCEL", "LOCK", "IOCTL",
            "CHANGE_NOTIFY", "OPLOCK_BREAK", "FLUSH"}


# ──────────────────────────────────────────────────────────────────────
# ESTRUCTURAS DE DATOS
# ──────────────────────────────────────────────────────────────────────

class PaqueteSMB2:
    """Un paquete SMB2 extraido del CSV."""
    def __init__(self, linea, comando, timestamp, tree_id,
                 file_id, file_path, create_options, info_class,
                 read_len, write_len, tiene_error):
        self.linea = linea
        self.comando = comando
        self.timestamp = timestamp
        self.tree_id = tree_id
        self.file_id = file_id
        self.file_path = file_path
        self.create_options = create_options
        self.info_class = info_class
        self.read_len = read_len
        self.write_len = write_len
        self.tiene_error = tiene_error

    def __repr__(self):
        return (f"[L{self.linea:4d} t={self.timestamp:.3f}] "
                f"{self.comando:16s} "
                f"FID={str(self.file_id or ''):20s} "
                f"{self.file_path or ''}")


class Operacion:
    """Una operacion de usuario: grupo de paquetes que forman una accion."""
    def __init__(self):
        self.paquetes = []
        self.tipo = "DESCONOCIDA"
        self.archivo = ""
        self.timestamp_inicio = 0.0
        self.timestamp_fin = 0.0
        self.linea_inicio = 0
        self.linea_fin = 0
        self.total_read = 0
        self.total_write = 0
        self.num_reads = 0
        self.num_writes = 0

    def anyadir(self, pkt):
        if not self.paquetes:
            self.timestamp_inicio = pkt.timestamp
            self.linea_inicio = pkt.linea
            if pkt.file_path:
                self.archivo = pkt.file_path
        else:
            if pkt.file_path and not self.archivo:
                self.archivo = pkt.file_path

        self.paquetes.append(pkt)
        self.timestamp_fin = pkt.timestamp
        self.linea_fin = pkt.linea

        if pkt.read_len:
            self.total_read += pkt.read_len
            self.num_reads += 1
        if pkt.write_len:
            self.total_write += pkt.write_len
            self.num_writes += 1

    @property
    def duracion_ms(self):
        return (self.timestamp_fin - self.timestamp_inicio) * 1000.0

    @property
    def num_paquetes(self):
        return len(self.paquetes)

    def resumen(self):
        archivo_corto = self.archivo
        if len(archivo_corto) > 45:
            archivo_corto = "..." + archivo_corto[-42:]
        return (f"{self.tipo:28s} | {archivo_corto or '(sin nombre)':45s} | "
                f"{self.num_paquetes:3d} paqs | "
                f"{self.duracion_ms:8.2f} ms | "
                f"Lineas [{self.linea_inicio}--{self.linea_fin}]")


# ──────────────────────────────────────────────────────────────────────
# LECTURA DEL CSV
# ──────────────────────────────────────────────────────────────────────

def leer_csv(ruta):
    """
    Lee el archivo CSV y devuelve una lista de PaqueteSMB2.
    Las filas 1-14 son cabeceras, los datos empiezan en la fila 17.
    """
    paquetes = []
    with open(ruta, "r", encoding="utf-8-sig") as f:
        lector = csv.reader(f)
        for num_fila, fila in enumerate(lector, 1):
            # Saltamos cabeceras (filas 1-14) y filas vacias
            if num_fila <= 15 or not fila or len(fila) < 10:
                continue

            comando = fila[9].strip().upper() if fila[9] else ""

            # Ignoramos comandos vacios o de ruido de OS
            if not comando or comando in RUIDO_OS:
                continue

            # Timestamp (columna 5 = inicio del request)
            try:
                timestamp = float(fila[5]) if fila[5] else 0.0
            except ValueError:
                timestamp = 0.0

            # Tree ID (columna 13)
            tree_id = None
            try:
                if fila[13].strip():
                    tree_id = int(float(fila[13]))
            except (ValueError, IndexError):
                pass

            # FileID (columna 14)
            file_id = None
            if len(fila) > 14:
                raw = fila[14].strip()
                if raw and raw != "0" and raw != "0.0":
                    file_id = raw

            # FilePath (columna 19) - solo para CREATE
            file_path = None
            if comando == "CREATE" and len(fila) > 19:
                raw = fila[19].strip()
                if raw:
                    file_path = raw

            # CreateOptions (columna 15) - para CREATE
            create_options = None
            if comando == "CREATE" and len(fila) > 15:
                try:
                    raw = fila[15].strip()
                    if raw:
                        create_options = int(raw)
                except ValueError:
                    pass

            # InfoClass (columna 16) - para SET_INFO
            info_class = None
            if comando == "SET_INFO" and len(fila) > 16:
                try:
                    raw = fila[16].strip()
                    if raw:
                        info_class = int(raw)
                except ValueError:
                    pass

            # Longitud de lectura/escritura (columna 15)
            read_len = None
            write_len = None
            if comando == "READ" and len(fila) > 15:
                try:
                    read_len = int(fila[15])
                except (ValueError, IndexError):
                    pass
            elif comando == "WRITE" and len(fila) > 15:
                try:
                    write_len = int(fila[15])
                except (ValueError, IndexError):
                    pass

            # Error?
            tiene_error = False
            try:
                if len(fila) > 10 and fila[10].strip():
                    tiene_error = int(fila[10]) == 1
            except ValueError:
                pass

            pkt = PaqueteSMB2(
                linea=num_fila,
                comando=comando,
                timestamp=timestamp,
                tree_id=tree_id,
                file_id=file_id,
                file_path=file_path,
                create_options=create_options,
                info_class=info_class,
                read_len=read_len,
                write_len=write_len,
                tiene_error=tiene_error,
            )
            paquetes.append(pkt)

    print(f"  >> Leidos {len(paquetes)} paquetes SMB2 (tras filtrar ruido)")
    return paquetes


# ──────────────────────────────────────────────────────────────────────
# AGRUPACION TEMPORAL
# ──────────────────────────────────────────────────────────────────────

def agrupar_por_operacion(paquetes):
    """
    Agrupa los paquetes en operaciones candidatas.

    Cada CREATE en SMB2 genera un FileID unico. Los comandos posteriores
    (READ, WRITE, CLOSE, SET_INFO) usan ese mismo FileID para referirse
    al archivo abierto.

    Por tanto, agrupamos por FileID: todos los paquetes con el mismo
    FileID pertenecen a la misma "sub-operacion" atomica.

    Si ademas hay paquetes SIN FileID (QUERY_DIRECTORY, QUERY_INFO),
    los agrupamos por TreeID (sesion) y cercania temporal.

    El resultado son operaciones atomicas (un solo CREATE+operacion+CLOSE)
    que luego clasificamos individualmente.
    """
    grupos = defaultdict(list)
    for pkt in paquetes:
        clave = pkt.file_id if pkt.file_id else f"TREE_{pkt.tree_id}"
        grupos[clave].append(pkt)

    operaciones = []
    for clave, pkts in grupos.items():
        pkts.sort(key=lambda p: p.timestamp)
        op_actual = Operacion()
        op_actual.anyadir(pkts[0])

        for pkt in pkts[1:]:
            salto = pkt.timestamp - op_actual.timestamp_fin
            if salto > UMBRAL_TEMPORAL_SEG:
                operaciones.append(op_actual)
                op_actual = Operacion()
            op_actual.anyadir(pkt)

        operaciones.append(op_actual)

    operaciones.sort(key=lambda op: op.timestamp_inicio)
    return operaciones


# ──────────────────────────────────────────────────────────────────────
# CLASIFICACION DE OPERACIONES
# ──────────────────────────────────────────────────────────────────────

def clasificar_operacion(op):
    """
    Corazon del analisis: dado un grupo de paquetes (ventana temporal),
    decide que operacion de usuario representa.

    Ahora los paquetes NO comparten necesariamente el mismo FileID.
    Una operacion de usuario (ej: subir un archivo a una carpeta)
    genera MULTIPLES FileIDs. Miramos el patron GLOBAL de comandos.
    """
    comandos = [p.comando for p in op.paquetes]
    tiene_create = "CREATE" in comandos
    tiene_read = "READ" in comandos
    tiene_write = "WRITE" in comandos
    tiene_close = "CLOSE" in comandos
    tiene_setinfo = "SET_INFO" in comandos
    tiene_find = "QUERY_DIRECTORY" in comandos
    tiene_queryinfo = "QUERY_INFO" in comandos

    # InfoClass de SET_INFO
    info_classes = set()
    for p in op.paquetes:
        if p.info_class is not None:
            info_classes.add(p.info_class)

    # CreateOptions del primer CREATE
    create_options = None
    for p in op.paquetes:
        if p.comando == "CREATE" and p.create_options is not None:
            create_options = p.create_options
            break

    num_creates = sum(1 for c in comandos if c == "CREATE")
    num_reads = sum(1 for c in comandos if c == "READ")
    num_writes = sum(1 for c in comandos if c == "WRITE")

    # ---- REGLA 1: LISTAR DIRECTORIO ----
    # Solo FIND (QUERY_DIRECTORY), sin CREATE ni CLOSE
    if tiene_find and not tiene_create and not tiene_close:
        return "LISTAR DIRECTORIO"

    # ---- REGLA 2: CONSULTAR METADATOS ----
    # Solo QUERY_INFO, sin operaciones de E/S
    if tiene_queryinfo and not tiene_create and not tiene_read and not tiene_write:
        return "CONSULTAR METADATOS"

    # ---- REGLA 3: CREAR CARPETA ----
    # Solo CREATEs con opcion directorio + CLOSE, sin READ/WRITE
    if (tiene_create and create_options is not None
            and (create_options & CREATE_OPTIONS_DIRECTORIO)
            and tiene_close and not tiene_read and not tiene_write):
        return "CREAR CARPETA"

    # ---- REGLA 4: BORRAR ARCHIVO ----
    # CREATE + SET_INFO(0x0D) + CLOSE, sin READ/WRITE
    if (tiene_create and INFO_CLASS_BORRAR in info_classes
            and tiene_close and not tiene_read and not tiene_write):
        return "BORRAR ARCHIVO"

    # ---- REGLA 5: RENOMBRAR/MOVER ----
    # CREATE + SET_INFO(0x0A) + CLOSE, sin READ/WRITE
    if (tiene_create and INFO_CLASS_RENOMBRAR in info_classes
            and tiene_close and not tiene_read and not tiene_write):
        return "RENOMBRAR/MOVER"

    # ---- REGLA 6: SUBIR ARCHIVO ----
    # CREATE + WRITE* + CLOSE (sin READ)
    if tiene_create and tiene_write and tiene_close and not tiene_read:
        return "SUBIR ARCHIVO"

    # ---- REGLA 7: BAJAR ARCHIVO ----
    # CREATE + READ* + CLOSE (sin WRITE)
    if tiene_create and tiene_read and tiene_close and not tiene_write:
        return "BAJAR ARCHIVO"

    # ---- REGLA 8: MODIFICAR ARCHIVO ----
    # CREATE + READ* + WRITE* + CLOSE
    if tiene_create and tiene_read and tiene_write and tiene_close:
        return "MODIFICAR ARCHIVO"

    # ---- Si no tiene nada de esto, es ruido ----
    if not tiene_create and not tiene_read and not tiene_write and not tiene_find:
        return "RUIDO/SIN OPERACION"

    return "DESCONOCIDA"


# ──────────────────────────────────────────────────────────────────────
# REPORTE
# ──────────────────────────────────────────────────────────────────────

def generar_reporte(operaciones, solo_resumen=False):
    """Muestra el reporte de operaciones detectadas."""
    if not solo_resumen:
        # Listado detallado de operaciones (solo si no estamos en modo resumen)
        print()
        print("=" * 95)
        print("  REPORTE DE OPERACIONES SMB2")
        print("=" * 95)
        print(f"  Total operaciones: {len(operaciones)}")
        print("=" * 95)
        print()

        print("  +-- OPERACIONES DETECTADAS -------------------------------+")
        for i, op in enumerate(operaciones, 1):
            print(f"  | [{i:4d}] {op.resumen()}")
        print("  +---------------------------------------------------------+")
        print()

    # Resumen por tipo (siempre sale, al final)
    conteo = defaultdict(int)
    for op in operaciones:
        conteo[op.tipo] += 1

    print("=" * 95)
    print("  RESUMEN FINAL - OPERACIONES POR TIPO")
    print("=" * 95)
    print("  +-- TIPO DE OPERACION                   TOTAL  -----------+")
    for tipo, num in sorted(conteo.items(), key=lambda x: -x[1]):
        print(f"  | {tipo:35s} -> {num:4d} {'vez' if num == 1 else 'veces'}")
    print("  +---------------------------------------------------------+")
    print()


# ──────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Uso: python analizador_smb2.py <archivo.csv> [--resumen]")
        print("Ejemplo: python analizador_smb2.py Trazas/Traza_user_5.csv")
        print("         python analizador_smb2.py Trazas/Traza_user_5.csv --resumen")
        sys.exit(1)

    ruta_csv = sys.argv[1]
    solo_resumen = "--resumen" in sys.argv

    if not os.path.isfile(ruta_csv):
        print(f"Error: No se encuentra el archivo: {ruta_csv}")
        sys.exit(1)

    if not solo_resumen:
        print()
        print("=" * 70)
        print("  ANALIZADOR DE TRAFICO SMB2")
        print(f"  Archivo: {ruta_csv}")
        print("=" * 70)
        print()

    # Paso 1: Leer CSV
    if not solo_resumen:
        print("[1] Leyendo archivo CSV...")
    paquetes = leer_csv(ruta_csv)

    if not paquetes:
        print("  >> No se encontraron paquetes SMB2.")
        sys.exit(0)

    # Paso 2: Agrupar por operacion
    if not solo_resumen:
        print()
        print("[2] Agrupando paquetes por operacion...")
    operaciones = agrupar_por_operacion(paquetes)
    if not solo_resumen:
        print(f"  >> {len(operaciones)} grupos formados")

    # Paso 3: Clasificar cada operacion
    if not solo_resumen:
        print()
        print("[3] Clasificando operaciones...")
    for op in operaciones:
        op.tipo = clasificar_operacion(op)
    if not solo_resumen:
        print("  >> Clasificacion completada")

    # Paso 4: Reporte
    if not solo_resumen:
        print()
        print("[4] Generando reporte...")
    generar_reporte(operaciones, solo_resumen=solo_resumen)

    if not solo_resumen:
        print()
        print("[*] Analisis completado.")
        print()


if __name__ == "__main__":
    main()
