#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analizador_smb2_v3.py — Analizador experimental SIN agrupar por FileID
===========================================================================
TFG: Caracterizacion tecnica del protocolo SMB2 mediante analisis de trafico

VERSION 3 — Experimental: sin agrupar_por_operacion()
--------------------------------------------------------
A diferencia de v2, esta version NO separa los paquetes por FileID antes de
clasificar. En su lugar, procesa todos los paquetes cronologicamente y
agrupa por ventanas CREATE+CLOSE a nivel global (multi-FileID).

Esto permite que el clasificador vea operaciones con multiples FileIDs
(COMPRIMIR ARCHIVO, COMPRIMIR CARPETA, COPIAR CARPETA, etc.) tal como
aparecen en la captura real.

Estrategia:
  1. Recorrer paquetes ordenados por timestamp.
  2. Al encontrar un CREATE, iniciar una operacion y anyadir todos los
     paquetes hasta que se cierren TODOS los FileIDs abiertos.
  3. Pasar la operacion completa (con todos sus FileIDs) al clasificador.

Uso:
    python src/analizador_smb2_v3.py Trazas/Traza_user_5.csv
    python src/analizador_smb2_v3.py Trazas/Traza_user_5.csv --resumen
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
                 file_id, file_path=None, create_options=None,
                 info_class=None, read_len=None, write_len=None,
                 read_offset=None, write_offset=None, tiene_error=False):
        self.linea = linea
        self.comando = comando
        self.timestamp = float(timestamp) if timestamp else 0.0
        self.tree_id = str(tree_id) if tree_id else None
        self.file_id = str(file_id) if file_id else None
        self.file_path = file_path
        self.create_options = create_options
        self.info_class = info_class
        self.read_len = int(read_len) if read_len else 0
        self.write_len = int(write_len) if write_len else 0
        self.read_offset = read_offset
        self.write_offset = write_offset
        self.tiene_error = tiene_error

    def __repr__(self):
        return (f"<{self.comando} ts={self.timestamp} "
                f"fid={self.file_id} tree={self.tree_id}>")


class Operacion:
    """Una operacion de usuario: grupo de paquetes que forman una accion."""

    def __init__(self):
        self.paquetes = []
        self.tipo = None
        self.timestamp_inicio = None
        self.timestamp_fin = None
        self.file_ids = set()

    def anyadir(self, pkt):
        self.paquetes.append(pkt)
        if pkt.file_id:
            self.file_ids.add(pkt.file_id)
        if self.timestamp_inicio is None or pkt.timestamp < self.timestamp_inicio:
            self.timestamp_inicio = pkt.timestamp
        if self.timestamp_fin is None or pkt.timestamp > self.timestamp_fin:
            self.timestamp_fin = pkt.timestamp

    def resumen(self):
        return (f"[{self.tipo or '?'}] "
                f"{self.timestamp_inicio:.3f}-{self.timestamp_fin:.3f} "
                f"({len(self.paquetes)} paqs, {len(self.file_ids)} FileIDs)")


# ──────────────────────────────────────────────────────────────────────
# LECTURA DE CSV
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
# AGRUPAMIENTO MULTI-FILEID (v3 experimental)
# ──────────────────────────────────────────────────────────────────────

def agrupar_por_ventana_global(paquetes):
    """
    Agrupa paquetes en operaciones usando ventanas CREATE+CLOSE globales.

    A diferencia de v2, NO separa por FileID. En su lugar:
      1. Recorre los paquetes cronologicamente.
      2. Al encontrar un CREATE, lo anyade a la operacion actual y
         registra su FileID como "abierto".
      3. Sigue anyadiendo paquetes hasta que TODOS los FileIDs abiertos
         se hayan cerrado con un CLOSE.
      4. Cuando todos estan cerrados, la operacion termina.

    Esto permite que operaciones multi-FileID (COMPRIMIR ARCHIVO, COPIAR
    CARPETA, etc.) se mantengan juntas en una sola operacion.

    Limitacion: si hay asincronia (paquetes de otra operacion entre
    medias), se mezclaran en la misma operacion.
    """
    operaciones = []
    op_actual = None
    # Conjunto de FileIDs actualmente abiertos (pendientes de CLOSE)
    fids_abiertos = set()
    # Contador de cuantos CLOSE hemos visto para cada FileID abierto
    closes_pendientes = defaultdict(int)

    for pkt in paquetes:
        if pkt.comando == "CREATE" and pkt.file_id:
            # Iniciar nueva operacion si no hay una activa
            if op_actual is None:
                op_actual = Operacion()

            op_actual.anyadir(pkt)
            fids_abiertos.add(pkt.file_id)
            closes_pendientes[pkt.file_id] += 1  # esperamos 1 CLOSE

        elif pkt.comando == "CLOSE" and pkt.file_id:
            if op_actual is not None:
                op_actual.anyadir(pkt)
                # Reducir contador de CLOSE pendiente para este FileID
                if pkt.file_id in closes_pendientes:
                    closes_pendientes[pkt.file_id] -= 1
                    if closes_pendientes[pkt.file_id] <= 0:
                        del closes_pendientes[pkt.file_id]
                        fids_abiertos.discard(pkt.file_id)

                # Si no quedan FileIDs abiertos, cerrar operacion
                if not fids_abiertos:
                    operaciones.append(op_actual)
                    op_actual = None
                    closes_pendientes.clear()
            else:
                # CLOSE huerfano (sin CREATE previo) -> operacion independiente
                op = Operacion()
                op.anyadir(pkt)
                operaciones.append(op)

        else:
            # Cualquier otro comando (READ, WRITE, SET_INFO, QUERY_DIRECTORY, etc.)
            # Solo se anyade si hay una operacion activa
            if op_actual is not None:
                op_actual.anyadir(pkt)
            # Si no hay operacion activa, se descarta (paquete huerfano)

    # Si queda una operacion abierta (CREATEs sin CLOSE)
    if op_actual is not None:
        op_actual.tipo = "DESCONOCIDA (CREATE sin CLOSE)"
        operaciones.append(op_actual)

    return operaciones


# ──────────────────────────────────────────────────────────────────────
# FUNCIONES AUXILIARES PARA CLASIFICACION
# ──────────────────────────────────────────────────────────────────────

def _info_classes_en_operacion(op):
    """Devuelve conjunto de InfoClass presentes en SET_INFOs de la operacion."""
    return {p.info_class for p in op.paquetes
            if p.comando == "SET_INFO" and p.info_class is not None}


def _primer_create_options(op):
    """Devuelve CreateOptions del primer CREATE de la operacion."""
    for p in op.paquetes:
        if p.comando == "CREATE":
            return p.create_options
    return None


def _es_directorio(create_options):
    """Determina si un CreateOptions corresponde a un directorio."""
    if create_options is None:
        return False
    return bool(create_options & CREATE_OPTIONS_DIRECTORIO)


def _contar_comando(op, comando):
    """Cuanta cuantas veces aparece un comando en la operacion."""
    return sum(1 for p in op.paquetes if p.comando == comando)


def _primer_write_offset_cero(op):
    """Comprueba si el primer WRITE tiene offset=0 (escritura desde inicio)."""
    for p in op.paquetes:
        if p.comando == "WRITE":
            return p.write_offset == 0
    return False


def _debug_op(op, mensaje=""):
    """Muestra informacion de depuracion de una operacion."""
    print(f"  --- DEBUG {mensaje} ---")
    print(f"  Paquetes ({len(op.paquetes)}):")
    for p in op.paquetes:
        print(f"    L{p.linea:>5} | {p.timestamp:>8.3f} | {p.comando:15s} | "
              f"FID={p.file_id}")
    print(f"  FileIDs: {op.file_ids}")
    print(f"  Duracion: {op.timestamp_inicio:.3f} - {op.timestamp_fin:.3f}")
    print()


# ──────────────────────────────────────────────────────────────────────
# CLASIFICACION DE OPERACIONES (identica a v2)
# ──────────────────────────────────────────────────────────────────────

def clasificar_operacion(op, debug=False):
    """
    Corazon del analisis: dado un grupo de paquetes, decide que operacion
    de usuario representa, segun las definiciones de la memoria TFG.

    Las reglas estan ordenadas de mas especifica a mas generica.
    (IDENTICA a la version v2)
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

    if debug:
        print(f"  Caracteristicas: creates={num_creates}, reads={num_reads}, "
              f"writes={num_writes}, finds={num_finds}, "
              f"setinfo={num_setinfo}, file_ids={num_file_ids}")
        print(f"  InfoClasses: {info_classes}")
        print(f"  Es_dir={es_dir}, IOCTL={tiene_ioctl}, QUERY_INFO={tiene_queryinfo}")

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
    # Secuencia: CREATE (con CreateOptions bit directorio) + CLOSE
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
    # Secuencia: CREATE + WRITE* + CLOSE
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
    # REGLA 20: RUIDO / SIN OPERACION
    # ==================================================================
    if not tiene_create and not tiene_read and not tiene_write and not tiene_find:
        return "RUIDO/SIN OPERACION"

    # ==================================================================
    # REGLA 21: Cualquier otra combinacion no reconocida
    # ==================================================================
    return "DESCONOCIDA"


# ──────────────────────────────────────────────────────────────────────
# GENERACION DE REPORTE
# ──────────────────────────────────────────────────────────────────────

def generar_reporte(operaciones, solo_resumen=False):
    """Genera un reporte con las operaciones clasificadas."""
    conteo = defaultdict(int)
    total = len(operaciones)

    for op in operaciones:
        conteo[op.tipo or "DESCONOCIDA"] += 1

    if solo_resumen:
        print(f"\n{'='*60}")
        print("  RESUMEN DE OPERACIONES DETECTADAS (v3 experimental)")
        print(f"{'='*60}")
        print(f"\n  Total operaciones: {total}")
        print()
        print(f"  {'Tipo de operacion':40s} {'Cantidad':>8s} {'%':>8s}")
        print(f"  {'-'*40} {'-'*8} {'-'*8}")
        for tipo, count in sorted(conteo.items(), key=lambda x: -x[1]):
            pct = 100.0 * count / total
            print(f"  {tipo:40s} {count:8d} {pct:7.1f}%")
        print()
        return

    print(f"\n{'='*60}")
    print("  REPORTE DE OPERACIONES DETECTADAS (v3 experimental)")
    print(f"{'='*60}")
    print(f"\nTotal operaciones: {total}")
    print()

    for i, op in enumerate(operaciones, 1):
        print(f"  {i:4d}. {op.resumen()}")

    print()
    print("  --- RESUMEN ---")
    print(f"  {'Tipo de operacion':40s} {'Cantidad':>8s} {'%':>8s}")
    print(f"  {'-'*40} {'-'*8} {'-'*8}")
    for tipo, count in sorted(conteo.items(), key=lambda x: -x[1]):
        pct = 100.0 * count / total
        print(f"  {tipo:40s} {count:8d} {pct:7.1f}%")


# ──────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Uso: python src/analizador_smb2_v3.py <archivo.csv> [--resumen]")
        sys.exit(1)

    ruta_csv = sys.argv[1]
    solo_resumen = "--resumen" in sys.argv

    if not os.path.exists(ruta_csv):
        print(f"Error: no se encuentra el archivo {ruta_csv}")
        sys.exit(1)

    print(f"Analizando {ruta_csv}...")
    paquetes = leer_csv(ruta_csv)
    print(f"  Paquetes SMB2 leidos: {len(paquetes)}")

    # v3: agrupar por ventana global (multi-FileID)
    operaciones = agrupar_por_ventana_global(paquetes)
    print(f"  Operaciones agrupadas: {len(operaciones)}")

    # Clasificar cada operacion
    for op in operaciones:
        op.tipo = clasificar_operacion(op)

    # Generar reporte
    generar_reporte(operaciones, solo_resumen=solo_resumen)


if __name__ == "__main__":
    main()
