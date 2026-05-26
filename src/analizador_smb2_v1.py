#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analizador_smb2.py — Analizador de operaciones de usuario en trazas SMB2
===========================================================================
TFG: Caracterizacion tecnica del protocolo SMB2 mediante analisis de trafico

Este script lee un CSV exportado de Wireshark con trazas SMB2, agrupa los
paquetes por operacion (mismo FileID y cercania temporal), y clasifica cada
grupo en una operacion de usuario segun las definiciones de la memoria TFG.

Uso:
    python analizador_smb2.py Trazas/Traza_user_5.csv
    python analizador_smb2.py Trazas/Traza_user_5.csv --resumen
"""

import csv
import sys
import os
from collections import defaultdict


# ──────────────────────────────────────────────────────────────────────
# CONSTANTES — InfoClass de SET_INFO (segun [MS-SMB2])
# ──────────────────────────────────────────────────────────────────────

INFO_CLASS_RENOMBRAR           = 0x0A  # FileRenameInformation
INFO_CLASS_BORRAR              = 0x0D  # FileDispositionInformation
INFO_CLASS_BASIC_INFO          = 0x04  # FileBasicInformation
INFO_CLASS_ALLOCATION_INFO     = 0x13  # FileAllocationInformation
INFO_CLASS_END_OF_FILE_INFO    = 0x14  # FileEndOfFileInformation

# CreateOptions de CREATE (columna 15)
CREATE_OPTIONS_DIRECTORIO      = 0x01  # FILE_DIRECTORY_FILE -> es carpeta

# Si entre dos paquetes del mismo FileID pasan mas de X segundos,
# los separamos en operaciones distintas
UMBRAL_TEMPORAL_SEG = 2.0

# Comandos de "ruido" del SO que ignoramos (mantenimiento de sesion/transporte)
RUIDO_OS = {"NEGOTIATE", "SESSION_SETUP", "LOGOFF", "TREE_CONNECT",
            "TREE_DISCONNECT", "ECHO", "CANCEL", "LOCK",
            "CHANGE_NOTIFY", "OPLOCK_BREAK", "FLUSH"}


# ──────────────────────────────────────────────────────────────────────
# ESTRUCTURAS DE DATOS
# ──────────────────────────────────────────────────────────────────────

class PaqueteSMB2:
    """Un paquete SMB2 extraido del CSV."""
    def __init__(self, linea, comando, timestamp, tree_id,
                 file_id, file_path, create_options, info_class,
                 read_len, write_len, read_offset, write_offset,
                 tiene_error):
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
        self.read_offset = read_offset
        self.write_offset = write_offset
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
        self.num_creates = 0
        self.num_closes = 0
        self.num_setinfo = 0
        self.num_finds = 0
        self.num_ioctls = 0
        self.file_ids = set()

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

        if pkt.file_id:
            self.file_ids.add(pkt.file_id)

        if pkt.comando == "CREATE":
            self.num_creates += 1
        elif pkt.comando == "CLOSE":
            self.num_closes += 1
        elif pkt.comando == "SET_INFO":
            self.num_setinfo += 1
        elif pkt.comando == "QUERY_DIRECTORY":
            self.num_finds += 1
        elif pkt.comando == "IOCTL":
            self.num_ioctls += 1

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
    Lee el archivo CSV (formato de las trazas de usuario)
    y devuelve una lista de PaqueteSMB2.
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

            # Longitud de lectura/escritura (columna 15 para READ/WRITE)
            read_len = None
            write_len = None
            read_offset = None
            write_offset = None
            if comando == "READ" and len(fila) > 15:
                try:
                    read_len = int(fila[15])
                except (ValueError, IndexError):
                    pass
                # Offset del READ (columna 17 si existe)
                if len(fila) > 17:
                    try:
                        read_offset = int(fila[17])
                    except (ValueError, IndexError):
                        pass
            elif comando == "WRITE" and len(fila) > 15:
                try:
                    write_len = int(fila[15])
                except (ValueError, IndexError):
                    pass
                # Offset del WRITE (columna 17 si existe)
                if len(fila) > 17:
                    try:
                        write_offset = int(fila[17])
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
                read_offset=read_offset,
                write_offset=write_offset,
                tiene_error=tiene_error,
            )
            paquetes.append(pkt)

    print(f"  >> Leidos {len(paquetes)} paquetes SMB2 (tras filtrar ruido)")
    return paquetes


# ──────────────────────────────────────────────────────────────────────
# AGRUPACION POR OPERACION
# ──────────────────────────────────────────────────────────────────────

def agrupar_por_operacion(paquetes):
    """
    Agrupa los paquetes en operaciones candidatas.

    Estrategia de agrupacion:
    - Paquetes CON FileID: se agrupan por FileID. Si hay un salto temporal
      mayor que UMBRAL_TEMPORAL_SEG entre dos paquetes del mismo FileID,
      se separan en distintas operaciones.
    - Paquetes SIN FileID (QUERY_DIRECTORY, QUERY_INFO): se agrupan por
      TreeID + cercania temporal.

    Cada grupo representa una operacion atomica (un solo FileID).
    Las operaciones compuestas (upload_folder, compress, etc.) se
    detectan a nivel de clasificacion, no de agrupacion.
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
# FUNCIONES AUXILIARES DE CLASIFICACION
# ──────────────────────────────────────────────────────────────────────

def _es_directorio(create_options):
    """True si CreateOptions indica que es un directorio (bit 0 = 1)."""
    return create_options is not None and (create_options & CREATE_OPTIONS_DIRECTORIO)


def _info_classes_en_operacion(op):
    """Devuelve el conjunto de InfoClass de todos los SET_INFO de la operacion."""
    clases = set()
    for p in op.paquetes:
        if p.info_class is not None:
            clases.add(p.info_class)
    return clases


def _primer_create_options(op):
    """Devuelve CreateOptions del primer CREATE de la operacion."""
    for p in op.paquetes:
        if p.comando == "CREATE" and p.create_options is not None:
            return p.create_options
    return None


def _primer_write_offset_cero(op):
    """Comprueba si el primer WRITE tiene Offset=0 (senial de upload completo)."""
    for p in op.paquetes:
        if p.comando == "WRITE":
            return p.write_offset == 0
    return False


def _tiene_comando(op, comando):
    return any(p.comando == comando for p in op.paquetes)


def _contar_comando(op, comando):
    return sum(1 for p in op.paquetes if p.comando == comando)


# ──────────────────────────────────────────────────────────────────────
# CLASIFICACION DE OPERACIONES
# ──────────────────────────────────────────────────────────────────────

def _debug_op(op, mensaje=""):
    """Imprime informacion de depuracion de una operacion."""
    print(f"  [DEBUG] {mensaje}")
    print(f"    Archivo: {op.archivo or '(sin nombre)'}")
    print(f"    Paquetes: {op.num_paquetes}, FileIDs: {len(op.file_ids)}")
    print(f"    Creates: {op.num_creates}, Reads: {op.num_reads}, Writes: {op.num_writes}")
    print(f"    SET_INFOs: {op.num_setinfo}, FINDs: {op.num_finds}, IOCTLs: {op.num_ioctls}")
    print(f"    Lineas [{op.linea_inicio}--{op.linea_fin}]")
    # Mostrar comandos unicos en orden
    vistos = []
    for p in op.paquetes:
        info = p.comando
        if p.comando == "CREATE" and p.create_options is not None:
            info += f"(opt={p.create_options})"
        if p.comando == "SET_INFO" and p.info_class is not None:
            info += f"(cls=0x{p.info_class:02X})"
        if p.comando in ("READ", "WRITE") and (p.read_len or p.write_len):
            info += f"(len={p.read_len or p.write_len})"
        if info not in vistos:
            vistos.append(info)
    print(f"    Comandos: {' '.join(vistos)}")
    print()


def clasificar_operacion(op, debug=False):
    """
    Corazon del analisis: dado un grupo de paquetes, decide que operacion
    de usuario representa, segun las definiciones de la memoria TFG.

    Las reglas estan ordenadas de mas especifica a mas generica.
    """
    # Extraer caracteristicas basicas
    comandos = [p.comando for p in op.paquetes]
    tiene_create = "CREATE" in comandos
    tiene_read = "READ" in comandos
    tiene_write = "WRITE" in comandos
    tiene_close = "CLOSE" in comandos
    tiene_setinfo = "SET_INFO" in comandos
    tiene_find = "QUERY_DIRECTORY" in comandos
    tiene_ioctl = "IOCTL" in comandos
    tiene_queryinfo = "QUERY_INFO" in comandos

    info_classes = _info_classes_en_operacion(op)
    create_options = _primer_create_options(op)
    es_dir = _es_directorio(create_options)

    num_creates = _contar_comando(op, "CREATE")
    num_reads = _contar_comando(op, "READ")
    num_writes = _contar_comando(op, "WRITE")
    num_finds = _contar_comando(op, "QUERY_DIRECTORY")
    num_setinfo = _contar_comando(op, "SET_INFO")
    num_file_ids = len(op.file_ids)

    # ==================================================================
    # REGLA 1: LISTAR DIRECTORIO
    # Secuencia: CREATE + FIND* + CLOSE
    # (Memoria TFG seccion 1.3.4.3)
    # ==================================================================
    if (tiene_create and tiene_find and tiene_close
            and not tiene_read and not tiene_write and not tiene_setinfo):
        return "LISTAR DIRECTORIO"

    # ==================================================================
    # REGLA 2: CREAR CARPETA
    # Secuencia: CREATE (con CreateOptions bit directorio) + FIND + CLOSE
    # (Memoria TFG seccion 1.3.1.1)
    # ==================================================================
    if (tiene_create and es_dir and tiene_close
            and not tiene_read and not tiene_write
            and not tiene_setinfo):
        return "CREAR CARPETA"

    # ==================================================================
    # REGLA 3: CREAR ARCHIVO VACIO
    # Secuencia: CREATE (sin bit directorio) + CLOSE
    # (Memoria TFG seccion 1.3.1.2)
    # ==================================================================
    if (tiene_create and not es_dir and tiene_close
            and not tiene_read and not tiene_write
            and not tiene_setinfo and not tiene_find):
        return "CREAR ARCHIVO VACIO"

    # ==================================================================
    # REGLA 4: BORRAR (archivo o carpeta)
    # Secuencia: CREATE + SET_INFO(FileDispositionInformation=0x0D) + CLOSE
    # (Memoria TFG secciones 1.3.4.1 y 1.3.4.2)
    # ==================================================================
    if (tiene_create and INFO_CLASS_BORRAR in info_classes
            and tiene_close and not tiene_read and not tiene_write):
        if es_dir:
            return "BORRAR CARPETA"
        else:
            return "BORRAR ARCHIVO"

    # ==================================================================
    # REGLA 5: RENOMBRAR / MOVER (archivo o carpeta)
    # Secuencia: CREATE + SET_INFO(FileRenameInformation=0x0A) + CLOSE
    # (Memoria TFG secciones 1.3.3.1, 1.3.3.2, 1.3.3.3, 3.3.4)
    # ==================================================================
    if (tiene_create and INFO_CLASS_RENOMBRAR in info_classes
            and tiene_close and not tiene_read and not tiene_write):
        if es_dir:
            return "RENOMBRAR/MOVER CARPETA"
        else:
            return "RENOMBRAR/MOVER ARCHIVO"

    # ==================================================================
    # REGLA 6: SUBIR ARCHIVO (Upload file)
    # Secuencia: CREATE + WRITE* (con Offset=0 inicial) + CLOSE
    # (Memoria TFG seccion 1.3.2.2)
    # ==================================================================
    if (tiene_create and tiene_write and tiene_close
            and not tiene_read and not tiene_find):
        return "SUBIR ARCHIVO"

    # ==================================================================
    # REGLA 7: BAJAR ARCHIVO (Download file)
    # Secuencia: CREATE + READ* + CLOSE
    # (Memoria TFG seccion 1.3.2.4)
    # ==================================================================
    if (tiene_create and tiene_read and tiene_close
            and not tiene_write and not tiene_find):
        return "BAJAR ARCHIVO"

    # ==================================================================
    # REGLA 8: SUBIR CARPETA (Upload folder)
    # Secuencia: CREATE(carpeta) + FIND + (por cada archivo: CREATE+WRITE*+CLOSE) + CLOSE
    # (Memoria TFG seccion 1.3.2.1)
    # ==================================================================
    if (tiene_create and tiene_find and tiene_write and tiene_close
            and not tiene_read and num_creates >= 2):
        return "SUBIR CARPETA"

    # ==================================================================
    # REGLA 9: BAJAR CARPETA (Download folder)
    # Secuencia: CREATE(carpeta) + FIND + (por cada archivo: CREATE+READ*+CLOSE) + CLOSE
    # (Memoria TFG seccion 1.3.2.3)
    # ==================================================================
    if (tiene_create and tiene_find and tiene_read and tiene_close
            and not tiene_write and num_creates >= 2):
        return "BAJAR CARPETA"

    # ==================================================================
    # REGLA 10: COPIAR ARCHIVO (subida a red)
    # Secuencia: CREATE + SET_INFO + WRITE* + CLOSE
    # (Memoria TFG seccion 1.3.5.2, flujo de subida)
    # ==================================================================
    if (tiene_create and tiene_setinfo and tiene_write and tiene_close
            and not tiene_read and not tiene_find):
        return "COPIAR ARCHIVO (subida)"

    # ==================================================================
    # REGLA 11: COPIAR ARCHIVO (descarga de red)
    # Secuencia: CREATE + READ* + CLOSE
    # (Memoria TFG seccion 1.3.5.2, flujo de descarga)
    # Nota: es identico a BAJAR ARCHIVO, pero lo distinguimos por contexto
    # ==================================================================
    if (tiene_create and tiene_read and tiene_close
            and not tiene_write and not tiene_find):
        # Ya capturado por BAJAR ARCHIVO (regla 7)
        pass

    # ==================================================================
    # REGLA 12: COPIAR CARPETA
    # Secuencia: CREATE(carpeta) + FIND + (READ*/WRITE* por cada archivo) + CLOSE
    # (Memoria TFG seccion 1.3.5.1)
    # ==================================================================
    if (tiene_create and tiene_find and tiene_read and tiene_write
            and tiene_close and num_creates >= 2):
        return "COPIAR CARPETA"

    # ==================================================================
    # REGLA 13: COMPRIMIR ARCHIVO (Compress file)
    # Secuencia: READ* (origen) + CREATE + SET_INFO(AllocationInfo) + WRITE* + CLOSE
    # (Memoria TFG seccion 1.3.5.4)
    # ==================================================================
    if (tiene_create and tiene_read and tiene_write and tiene_close
            and INFO_CLASS_ALLOCATION_INFO in info_classes
            and num_file_ids >= 2):
        return "COMPRIMIR ARCHIVO"

    # ==================================================================
    # REGLA 14: COMPRIMIR CARPETA (Compress folder)
    # Secuencia: FIND + READ* (multiples archivos) + CREATE + WRITE* + CLOSE
    # (Memoria TFG seccion 1.3.5.3)
    # ==================================================================
    if (tiene_find and tiene_read and tiene_write and tiene_create
            and tiene_close and num_file_ids >= 3):
        return "COMPRIMIR CARPETA"

    # ==================================================================
    # REGLA 15: MODIFICAR ARCHIVO (con Notepad / editor grafico)
    # Secuencia: CREATE+READ*+CLOSE (lectura) + CREATE+SET_INFO+WRITE*+IOCTL+CLOSE (escritura)
    # (Memoria TFG seccion 1.3.6.1)
    # ==================================================================
    if (tiene_create and tiene_read and tiene_write and tiene_close
            and tiene_ioctl and num_file_ids >= 2):
        return "MODIFICAR ARCHIVO (editor)"

    # ==================================================================
    # REGLA 16: MODIFICAR ARCHIVO (comando atomico / copy con)
    # Secuencia: CREATE + SET_INFO + WRITE* + CLOSE
    # (Memoria TFG seccion 1.3.6.1, optimizacion)
    # ==================================================================
    if (tiene_create and tiene_setinfo and tiene_write and tiene_close
            and not tiene_read and not tiene_find):
        # Podria ser COPIAR ARCHIVO (subida) o MODIFICAR ATOMICO
        # Los distinguimos por la presencia de FileEndOfFileInformation
        if INFO_CLASS_END_OF_FILE_INFO in info_classes:
            return "MODIFICAR ARCHIVO (atomico)"
        return "COPIAR ARCHIVO (subida)"

    # ==================================================================
    # REGLA 17: CONSULTAR METADATOS
    # Solo QUERY_INFO, sin operaciones de E/S
    # ==================================================================
    if tiene_queryinfo and not tiene_create and not tiene_read and not tiene_write:
        return "CONSULTAR METADATOS"

    # ==================================================================
    # REGLA 18: CICLO CREATE+CLOSE EFIMERO (apertura sin operacion de datos)
    # ==================================================================
    if tiene_create and tiene_close and not tiene_read and not tiene_write and not tiene_setinfo and not tiene_find:
        if es_dir:
            return "APERTURA EFIMERA CARPETA"
        return "APERTURA EFIMERA ARCHIVO"

    # ==================================================================
    # REGLA 19: OPERACION COMPLEJA CON READ+WRITE+SET_INFO
    # ==================================================================
    if (tiene_create and tiene_read and tiene_write
            and tiene_close and num_creates >= 3
            and not tiene_find):
        if INFO_CLASS_BORRAR in info_classes and INFO_CLASS_RENOMBRAR in info_classes:
            return "OPERACION COMPLEJA (modif+borrar+renombrar)"
        if INFO_CLASS_BORRAR in info_classes:
            return "OPERACION COMPLEJA (modif+borrar)"
        if INFO_CLASS_RENOMBRAR in info_classes:
            return "OPERACION COMPLEJA (modif+renombrar)"
        return "OPERACION COMPLEJA (modif masiva)"

    # ==================================================================
    # REGLA 24: RUIDO / SIN OPERACION
    # ==================================================================
    if not tiene_create and not tiene_read and not tiene_write and not tiene_find:
        return "RUIDO/SIN OPERACION"

    # ==================================================================
    # REGLA 25: Cualquier otra combinacion no reconocida
    # ==================================================================
    return "DESCONOCIDA"


# ──────────────────────────────────────────────────────────────────────
# REPORTE
# ──────────────────────────────────────────────────────────────────────

def generar_reporte(operaciones, solo_resumen=False):
    """Muestra el reporte de operaciones detectadas."""
    if not solo_resumen:
        print()
        print("=" * 110)
        print("  REPORTE DE OPERACIONES SMB2")
        print("=" * 110)
        print(f"  Total operaciones: {len(operaciones)}")
        print("=" * 110)
        print()

        print("  +-- OPERACIONES DETECTADAS ---------------------------------------+")
        for i, op in enumerate(operaciones, 1):
            print(f"  | [{i:4d}] {op.resumen()}")
        print("  +---------------------------------------------------------+")
        print()

    # Resumen por tipo (siempre sale, al final)
    conteo = defaultdict(int)
    for op in operaciones:
        conteo[op.tipo] += 1

    print("=" * 110)
    print("  RESUMEN FINAL - OPERACIONES POR TIPO")
    print("=" * 110)
    print("  +-- TIPO DE OPERACION                        TOTAL  -----------+")
    for tipo, num in sorted(conteo.items(), key=lambda x: -x[1]):
        print(f"  | {tipo:40s} -> {num:4d} {'vez' if num == 1 else 'veces'}")
    print("  +---------------------------------------------------------+")
    print()


# ──────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Uso: python analizador_smb2.py <archivo.csv> [--resumen] [--debug]")
        print("Ejemplo: python analizador_smb2.py Trazas/Traza_user_5.csv")
        print("         python analizador_smb2.py Trazas/Traza_user_5.csv --resumen")
        print("         python analizador_smb2.py Trazas/Traza_user_5.csv --debug")
        sys.exit(1)

    ruta_csv = sys.argv[1]
    solo_resumen = "--resumen" in sys.argv
    modo_debug = "--debug" in sys.argv

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
        op.tipo = clasificar_operacion(op, debug=modo_debug)
        if modo_debug and op.tipo == "DESCONOCIDA":
            _debug_op(op, "OPERACION DESCONOCIDA")
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
