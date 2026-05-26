#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analizador_smb2_v4.py — Analizador SMB2 con operaciones simples y compuestas
============================================================================
TFG: Caracterizacion tecnica del protocolo SMB2 mediante analisis de trafico

VERSION 4 — Agrupacion jerarquica con deteccion de operaciones compuestas
----------------------------------------------------------------------
Estrategia de agrupacion:
  1. El primer CREATE de la traza es el "raiz" de una operacion compuesta.
  2. Cualquier CREATE que aparezca DENTRO del intervalo [CREATE_raiz, CLOSE_raiz]
     es un "subordinado" y pertenece a la misma operacion compuesta.
  3. La operacion compuesta se cierra cuando se encuentra el CLOSE del FileID raiz.
  4. Los paquetes de subordinados que esten FUERA de su propio intervalo
     CREATE→CLOSE pero DENTRO del intervalo raiz se incluyen igualmente.
  5. Los paquetes sin CREATE propio dentro del intervalo raiz se descartan.
  6. De cada operacion compuesta se extraen operaciones atomicas (1 FileID c/u)
     que se clasifican con el clasificador clasico de v2.
  7. Las operaciones compuestas (multi-FileID) se clasifican con un clasificador
     especifico que opera sobre los paquetes raw.

Uso:
    python src/analizador_smb2_v4.py Trazas/Traza_user_5.csv
    python src/analizador_smb2_v4.py Trazas/Traza_user_5.csv --resumen
"""

import csv
import sys
import os
import uuid
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
    """Una operacion atomica: grupo de paquetes de un mismo FileID."""
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
        self.id_compuesta = None  # UUID de la OperacionCompuesta a la que pertenece

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


class OperacionCompuesta:
    """Una operacion que puede ser simple (1 FileID) o compuesta (multiples FileIDs).

    Contiene:
    - paquetes: todos los paquetes en orden cronologico (raw)
    - operaciones_atomicas: lista de Operacion (1 por FileID)
    - es_simple: True si tiene exactamente 1 FileID
    - tipo_atomica: clasificacion si es simple (ej: "SUBIR ARCHIVO")
    - tipo_compuesta: clasificacion si es compuesta (ej: "COMPRIMIR ARCHIVO")
    """
    def __init__(self, id_compuesta, fileid_raiz):
        self.id = id_compuesta
        self.fileid_raiz = fileid_raiz
        self.paquetes = []
        self.timestamp_inicio = 0.0
        self.timestamp_fin = 0.0
        self.linea_inicio = 0
        self.linea_fin = 0
        self.operaciones_atomicas = []
        self.es_simple = True
        self.tipo_atomica = None
        self.tipo_compuesta = None

    def anyadir(self, pkt):
        if not self.paquetes:
            self.timestamp_inicio = pkt.timestamp
            self.linea_inicio = pkt.linea
        self.paquetes.append(pkt)
        self.timestamp_fin = pkt.timestamp
        self.linea_fin = pkt.linea

    @property
    def num_paquetes(self):
        return len(self.paquetes)

    @property
    def duracion_ms(self):
        return (self.timestamp_fin - self.timestamp_inicio) * 1000.0

    @property
    def file_ids(self):
        return set(p.file_id for p in self.paquetes if p.file_id)

    @property
    def num_file_ids(self):
        return len(self.file_ids)

    def resumen(self):
        tipo = self.tipo_compuesta or self.tipo_atomica or "SIN CLASIFICAR"
        fid_info = f"{self.num_file_ids} FileIDs" if not self.es_simple else "1 FileID"
        return (f"{tipo:32s} | {fid_info:14s} | "
                f"{self.num_paquetes:4d} paqs | "
                f"{self.duracion_ms:8.2f} ms | "
                f"Lineas [{self.linea_inicio}--{self.linea_fin}]")


# ──────────────────────────────────────────────────────────────────────
# LECTURA DEL CSV
# ──────────────────────────────────────────────────────────────────────

def _detectar_formato(ruta):
    """
    Detecta el formato del archivo de traza.
    Lee las primeras lineas y decide si es CSV (coma-separado con cabeceras)
    o TXT (espacio-separado, formato salidaSemana).

    Returns:
        str: "csv" si es formato CSV, "txt" si es espacio-separado.
    """
    try:
        with open(ruta, "r", encoding="utf-8-sig", errors="replace") as f:
            primeras = [next(f).strip() for _ in range(5) if f]
    except Exception:
        return "csv"  # por defecto

    if not primeras:
        return "csv"

    # Si la primera linea tiene comas y palabras como "Client IP" -> CSV con cabeceras
    if "," in primeras[0] and ("Client" in primeras[0] or "IP" in primeras[0]):
        return "csv"

    # Si la primera linea tiene comas y muchas columnas -> CSV sin cabeceras
    if "," in primeras[0]:
        num_cols = len(primeras[0].split(","))
        if num_cols >= 15:
            return "csv"

    # Si las lineas estan separadas por espacios y tienen numeros + comandos -> TXT
    for linea in primeras:
        partes = linea.split()
        if len(partes) >= 10:
            # Buscar si alguna parte parece un comando SMB2 conocido
            for p in partes:
                if p.upper() in {"CREATE", "CLOSE", "READ", "WRITE", "SET_INFO",
                                 "QUERY_DIRECTORY", "QUERY_INFO", "IOCTL",
                                 "NEGOTIATE", "SESSION_SETUP", "TREE_CONNECT"}:
                    return "txt"

    return "csv"  # por defecto


def _leer_csv_formato(ruta):
    """
    Lee archivo CSV (coma-separado) con el formato de Traza_user_5.csv.
    Las filas 1-14 son cabeceras, los datos empiezan en la fila 17.
    Columnas: [0]IP_src [1]Port_src [2]IP_dst [3]Port_dst [4]ConnID
              [5]Timestamp [6-8]vacio [9]Comando [10]Error
              [11-12]vacio [13]TreeID [14]FileID
              [15]CreateOptions/Length [16]InfoClass [17]Offset [18]vacio [19]FilePath
    """
    paquetes = []
    errores_columna = 0

    with open(ruta, "r", encoding="utf-8-sig", errors="replace") as f:
        lector = csv.reader(f)
        for num_fila, fila in enumerate(lector, 1):
            # Saltamos cabeceras (filas 1-14) y filas vacias
            if num_fila <= 15 or not fila or len(fila) < 10:
                continue

            comando = fila[9].strip().upper() if len(fila) > 9 and fila[9] else ""

            # Ignoramos comandos vacios o de ruido de OS
            if not comando or comando in RUIDO_OS:
                continue

            # Validar que tenemos suficientes columnas
            if len(fila) < 15:
                errores_columna += 1
                if errores_columna <= 5:
                    print(f"  [AVISO] Linea {num_fila}: solo {len(fila)} columnas (esperadas >=15). "
                          f"Comando={comando}")
                continue

            # Timestamp (columna 5 = inicio del request)
            try:
                timestamp = float(fila[5]) if fila[5] else 0.0
            except (ValueError, IndexError):
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
            raw = fila[14].strip() if len(fila) > 14 else ""
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

    if errores_columna > 0:
        print(f"  [AVISO] Total lineas con columnas insuficientes: {errores_columna}")
    print(f"  >> Leidos {len(paquetes)} paquetes SMB2 (formato CSV)")
    return paquetes


def _leer_txt_formato(ruta):
    """
    Lee archivo TXT espacio-separado con el formato de salidaSemana.txt.
    Columnas:
      [0]IP_src [1]Port_src [2]IP_dst [3]Port_dst [4]SessionID
      [5]TimestampReq1 [6]TimestampReq2 [7]TimestampResp1 [8]TimestampResp2
      [9]Comando [10]Status [11]Hex [12]ID1 [13]TreeID [14]FileID
      [15+]Campos especificos del comando

    CREATE:   [15]CreateOptions [16]0 [17]Size [18]AllocationSize [19]FilePath
    CLOSE:    solo hasta [14]FileID
    READ:     [15]Length [16]Offset [17]DataLength [18]DataRemaining
    WRITE:    [15]Length [16]Offset [17]DataLength
    SET_INFO: [15]FileID2 [16]InfoType [17]InfoClass
    QUERY_INFO: [15]FileID2 [16]InfoType [17]InfoClass
    QUERY_DIRECTORY: solo hasta [14]FileID
    IOCTL:    [14]CtlCode
    """
    paquetes = []
    errores_columna = 0
    num_linea = 0

    with open(ruta, "r", encoding="latin-1") as f:
        for linea_raw in f:
            num_linea += 1
            linea = linea_raw.strip()
            if not linea:
                continue

            partes = linea.split()
            if len(partes) < 10:
                errores_columna += 1
                if errores_columna <= 5:
                    print(f"  [AVISO] Linea {num_linea}: solo {len(partes)} columnas (esperadas >=10)")
                continue

            comando = partes[9].strip().upper()

            # Ignoramos comandos de ruido de OS
            if comando in RUIDO_OS:
                continue

            # Validar que el comando es conocido
            if comando not in {"CREATE", "CLOSE", "READ", "WRITE", "SET_INFO",
                               "QUERY_DIRECTORY", "QUERY_INFO", "IOCTL"}:
                errores_columna += 1
                if errores_columna <= 5:
                    print(f"  [AVISO] Linea {num_linea}: comando desconocido '{comando}'")
                continue

            # Timestamp (columna 5 = primer timestamp del request)
            try:
                timestamp = float(partes[5]) if partes[5] else 0.0
            except ValueError:
                timestamp = 0.0

            # Tree ID (columna 13)
            tree_id = None
            try:
                if partes[13].strip():
                    tree_id = int(float(partes[13]))
            except (ValueError, IndexError):
                pass

            # FileID (columna 14)
            file_id = None
            raw = partes[14] if len(partes) > 14 else ""
            # Un FileID valido no puede ser "0", vacio, ni un GUID de ceros
            if raw and raw != "0" and raw != "00000000000000000000000000000000":
                file_id = raw

            # Valores por defecto
            file_path = None
            create_options = None
            info_class = None
            read_len = None
            write_len = None
            read_offset = None
            write_offset = None
            tiene_error = False

            # Error (columna 10)
            try:
                if partes[10].strip():
                    tiene_error = int(partes[10]) == 1
            except (ValueError, IndexError):
                pass

            if comando == "CREATE":
                # CREATE: [14]FileID [15]CreateOptions [16]0 [17]Size [18]AllocationSize [19]FilePath
                if len(partes) >= 16:
                    try:
                        create_options = int(partes[15])
                    except ValueError:
                        pass
                if len(partes) >= 20:
                    file_path = partes[19]

            elif comando == "READ":
                # READ: [14]FileID [15]Length [16]Offset [17]DataLength [18]DataRemaining
                if len(partes) >= 16:
                    try:
                        read_len = int(partes[15])
                    except ValueError:
                        pass
                if len(partes) >= 17:
                    try:
                        read_offset = int(partes[16])
                    except ValueError:
                        pass

            elif comando == "WRITE":
                # WRITE: [14]FileID [15]Length [16]Offset [17]DataLength
                if len(partes) >= 16:
                    try:
                        write_len = int(partes[15])
                    except ValueError:
                        pass
                if len(partes) >= 17:
                    try:
                        write_offset = int(partes[16])
                    except ValueError:
                        pass

            elif comando == "SET_INFO":
                # SET_INFO: [14]FileID [15]FileID2 [16]InfoType [17]InfoClass
                if len(partes) >= 18:
                    try:
                        info_class = int(partes[17])
                    except ValueError:
                        pass

            # QUERY_INFO, QUERY_DIRECTORY, IOCTL, CLOSE: solo usamos FileID

            pkt = PaqueteSMB2(
                linea=num_linea,
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

    if errores_columna > 0:
        print(f"  [AVISO] Total lineas con errores: {errores_columna}")
    print(f"  >> Leidos {len(paquetes)} paquetes SMB2 (formato TXT)")
    return paquetes


def leer_csv(ruta):
    """
    Lee un archivo de traza (CSV o TXT espacio-separado) y devuelve
    una lista de PaqueteSMB2.

    Detecta automaticamente el formato:
    - CSV: coma-separado, con cabeceras (formato Traza_user_5.csv)
    - TXT: espacio-separado (formato salidaSemana.txt)

    Si el archivo tiene extension .ods, muestra un error indicando
    que debe exportarse a CSV desde LibreOffice.
    """
    # Comprobar extension
    ext = os.path.splitext(ruta)[1].lower()
    if ext == ".ods":
        print("  [ERROR] Formato .ods no soportado directamente.")
        print("          Exporta la hoja a CSV desde LibreOffice:")
        print("          Archivo > Exportar > Formato CSV")
        print("          O usa: File > Save As > CSV")
        return []

    # Detectar formato
    fmt = _detectar_formato(ruta)
    print(f"  >> Formato detectado: {'CSV' if fmt == 'csv' else 'TXT (espacio-separado)'}")

    if fmt == "csv":
        return _leer_csv_formato(ruta)
    else:
        return _leer_txt_formato(ruta)


# ──────────────────────────────────────────────────────────────────────
# AGRUPACION POR OPERACION (V4: jerarquia raiz/subordinados)
# ──────────────────────────────────────────────────────────────────────

def _pre_escanear_fids_con_close(paquetes):
    """
    Pre-escanear los paquetes para identificar que FileIDs tienen al menos
    un CLOSE. Esto permite que solo los CREATEs con CLOSE confirmado puedan
    ser raiz de una operacion compuesta.

    Devuelve un set con los FileIDs que tienen CLOSE.
    """
    fids_con_close = set()
    for pkt in paquetes:
        if pkt.file_id and pkt.comando == "CLOSE":
            fids_con_close.add(pkt.file_id)
    return fids_con_close


def agrupar_por_operacion_v4(paquetes):
    """
    Agrupa los paquetes en operaciones compuestas usando el algoritmo
    de jerarquia raiz/subordinados.

    Algoritmo:
      1. Pre-escanear todos los paquetes para identificar que FileIDs
         tienen al menos un CLOSE (fids_con_close).
      2. Recorrer paquetes en orden cronologico.
      3. Al encontrar un CREATE con FileID que TIENE CLOSE y no hay
         operacion activa:
         - Este CREATE es el "raiz" de una nueva OperacionCompuesta.
         - Se registra su FileID como fid_raiz.
         - Se inicializa el conjunto de FileIDs abiertos.
      4. Al encontrar un CREATE con FileID que NO tiene CLOSE:
         - Se descarta (es un CREATE huerfano/muerto).
         - Si hay operacion activa, se ignora (no se anyade).
      5. Al encontrar un CREATE con operacion activa y FileID con CLOSE:
         - Es un subordinado. Se anyade al conjunto de FileIDs abiertos.
      6. Al encontrar un CLOSE:
         - Si es de un FileID abierto, se anyade el paquete.
         - Si es del fid_raiz, se cierra la operacion compuesta.
      7. Cualquier otro comando (READ, WRITE, SET_INFO, etc.):
         - Si su FileID esta en el conjunto de abiertos, se anyade.
         - Si no, se descarta (pertenece a operacion anterior o es huerfano).
      8. Paquetes sin FileID (QUERY_DIRECTORY, QUERY_INFO):
         - Si hay operacion activa, se anyaden a la operacion actual
           (estan dentro del rango CREATE raiz - CLOSE raiz).
         - Si no hay operacion activa, se guardan para agrupar al final
           por TreeID con ventana temporal de 2s (igual que v2).

    Beneficio del pre-escaneo:
    - Los CREATEs sin CLOSE (CREATES huerfanos) no pueden ser raiz.
    - Esto evita que un CREATE sin CLOSE capture toda la traza restante.
    - Solo los FileIDs con ciclo CREATE+CLOSE completo forman operaciones.

    Integracion de FINDs:
    - Los QUERY_DIRECTORY (FIND) y QUERY_INFO no tienen FileID, por lo que
      en v2 se procesaban aparte. En v4, si aparecen dentro del rango de
      una operacion activa (entre su CREATE raiz y su CLOSE raiz), se
      integran en ella. Esto permite clasificar correctamente operaciones
      como BAJAR CARPETA o SUBIR CARPETA que requieren FIND.
    """
    # Pre-escanear FileIDs que tienen CLOSE
    fids_con_close = _pre_escanear_fids_con_close(paquetes)
    print(f"  >> Pre-escaneo: {len(fids_con_close)} FileIDs con CLOSE detectados")

    operaciones = []
    op_actual = None
    fids_abiertos = {}       # {fileid: timestamp_del_create}
    fids_abiertos_original = set()  # FileIDs que estaban abiertos al inicio
    fid_raiz = None

    # Paquetes sin FileID para agrupar al final (solo los que quedan
    # fuera de cualquier operacion activa)
    grupos_sin_fid = []

    creates_sin_close = 0
    creates_con_close = 0
    finds_integrados = 0

    for pkt in paquetes:
        # --- Paquetes SIN FileID (QUERY_DIRECTORY, QUERY_INFO) ---
        if not pkt.file_id:
            if op_actual is not None:
                # Hay operacion activa -> integrar el FIND/QUERY_INFO
                # en la operacion actual (esta dentro del rango
                # CREATE raiz - CLOSE raiz)
                op_actual.anyadir(pkt)
                finds_integrados += 1
            else:
                # No hay operacion activa -> guardar para agrupar al final
                grupos_sin_fid.append(pkt)
            continue

        # --- Paquetes CON FileID ---

        if pkt.comando == "CREATE":
            if pkt.file_id not in fids_con_close:
                # CREATE sin CLOSE -> descartar (huerfano/muerto)
                creates_sin_close += 1
                continue

            creates_con_close += 1

            if op_actual is None:
                # Nuevo CREATE raiz -> iniciar operacion compuesta
                fid_raiz = pkt.file_id
                op_actual = OperacionCompuesta(
                    id_compuesta=str(uuid.uuid4()),
                    fileid_raiz=fid_raiz,
                )
                op_actual.anyadir(pkt)
                fids_abiertos = {fid_raiz: pkt.timestamp}
                fids_abiertos_original = {fid_raiz}
            else:
                # Ya hay una operacion activa.
                if pkt.file_id == fid_raiz:
                    # Segundo CREATE del raiz -> el raiz anterior se queda
                    # sin CLOSE (no cerro). Cerramos la operacion actual
                    # y empezamos una nueva con este CREATE como nuevo raiz.
                    op_actual.es_simple = (len(fids_abiertos_original) == 1)
                    operaciones.append(op_actual)

                    fid_raiz = pkt.file_id
                    op_actual = OperacionCompuesta(
                        id_compuesta=str(uuid.uuid4()),
                        fileid_raiz=fid_raiz,
                    )
                    op_actual.anyadir(pkt)
                    fids_abiertos = {fid_raiz: pkt.timestamp}
                    fids_abiertos_original = {fid_raiz}
                else:
                    # CREATE subordinado
                    if pkt.file_id not in fids_abiertos:
                        fids_abiertos[pkt.file_id] = pkt.timestamp
                        fids_abiertos_original.add(pkt.file_id)
                    op_actual.anyadir(pkt)

        elif pkt.comando == "CLOSE":
            if op_actual is not None and pkt.file_id in fids_abiertos:
                op_actual.anyadir(pkt)
                del fids_abiertos[pkt.file_id]

                if pkt.file_id == fid_raiz:
                    # Se cerro el raiz -> cerrar operacion compuesta
                    op_actual.es_simple = (len(fids_abiertos_original) == 1)
                    operaciones.append(op_actual)
                    op_actual = None
                    fids_abiertos = {}
                    fids_abiertos_original = set()
                    fid_raiz = None
            # Si el CLOSE no es de un FileID abierto, se descarta

        else:
            # Cualquier otro comando (READ, WRITE, SET_INFO, etc.)
            if op_actual is not None:
                if pkt.file_id in fids_abiertos:
                    op_actual.anyadir(pkt)
            # Si no esta en fids_abiertos, se descarta
            # (pertenece a operacion anterior o es huerfano)

    # Si quedo una operacion sin cerrar (CREATE raiz sin CLOSE)
    if op_actual is not None:
        op_actual.es_simple = (len(fids_abiertos_original) == 1)
        operaciones.append(op_actual)

    if creates_sin_close > 0:
        print(f"  >> CREATEs sin CLOSE descartados: {creates_sin_close}")
    if finds_integrados > 0:
        print(f"  >> FINDs/QUERY_INFO integrados en operaciones activas: {finds_integrados}")

    # --- Procesar paquetes SIN FileID restantes (fuera de operaciones activas) ---
    # Los agrupamos por TreeID con ventana temporal (igual que v2)
    grupos_tree = defaultdict(list)
    for pkt in grupos_sin_fid:
        clave = f"TREE_{pkt.tree_id}" if pkt.tree_id is not None else "SIN_TREE"
        grupos_tree[clave].append(pkt)

    UMBRAL_TEMPORAL_SEG = 2.0
    for clave, pkts in grupos_tree.items():
        pkts.sort(key=lambda p: p.timestamp)
        op_comp = OperacionCompuesta(
            id_compuesta=str(uuid.uuid4()),
            fileid_raiz=None,
        )
        op_comp.anyadir(pkts[0])

        for pkt in pkts[1:]:
            salto = pkt.timestamp - op_comp.timestamp_fin
            if salto > UMBRAL_TEMPORAL_SEG:
                operaciones.append(op_comp)
                op_comp = OperacionCompuesta(
                    id_compuesta=str(uuid.uuid4()),
                    fileid_raiz=None,
                )
            op_comp.anyadir(pkt)

        operaciones.append(op_comp)

    operaciones.sort(key=lambda op: op.timestamp_inicio)
    return operaciones


# ──────────────────────────────────────────────────────────────────────
# EXTRACCION DE OPERACIONES ATOMICAS
# ──────────────────────────────────────────────────────────────────────

def extraer_operaciones_atomicas(op_compuesta):
    """
    Toma los paquetes de una operacion compuesta y extrae las operaciones
    atomicas (1 FileID cada una) que la componen.

    Para cada FileID, se crea una Operacion con todos sus paquetes
    en orden cronologico.
    """
    atomicas = []

    # Separar paquetes por FileID
    grupos = defaultdict(list)
    for pkt in op_compuesta.paquetes:
        if pkt.file_id:
            grupos[pkt.file_id].append(pkt)

    # Para cada FileID, crear una Operacion
    for fid, pkts in grupos.items():
        pkts.sort(key=lambda p: p.timestamp)
        op = Operacion()
        op.id_compuesta = op_compuesta.id
        for pkt in pkts:
            op.anyadir(pkt)
        atomicas.append(op)

    return atomicas


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


# ──────────────────────────────────────────────────────────────────────
# CLASIFICACION DE OPERACIONES ATOMICAS (reutilizada de v2)
# ──────────────────────────────────────────────────────────────────────

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
# CLASIFICADOR DE OPERACIONES COMPUESTAS (multi-FileID)
# ──────────────────────────────────────────────────────────────────────

def _info_classes_en_paquetes(paquetes):
    """Devuelve el conjunto de InfoClass de todos los SET_INFO en una lista de paquetes."""
    clases = set()
    for p in paquetes:
        if p.info_class is not None:
            clases.add(p.info_class)
    return clases


def _primer_create_options_de_paquetes(paquetes):
    """Devuelve CreateOptions del primer CREATE en una lista de paquetes."""
    for p in paquetes:
        if p.comando == "CREATE" and p.create_options is not None:
            return p.create_options
    return None


def _es_copiar_carpeta(paquetes, comandos, fileids, creates):
    """
    Regla 12: COPIAR CARPETA
    CREATE(carpeta) + FIND + (READ*/WRITE* por cada archivo) + CLOSE*
    Necesita: >=2 FileIDs, CREATE de carpeta, FIND, READ y WRITE.
    """
    if len(fileids) < 2:
        return False
    if "QUERY_DIRECTORY" not in comandos:
        return False
    if "READ" not in comandos or "WRITE" not in comandos:
        return False
    # El primer CREATE debe ser de carpeta
    first_create = creates[0] if creates else None
    if first_create is None or not _es_directorio(first_create.create_options):
        return False
    return True


def _es_comprimir_archivo(paquetes, comandos, fileids, creates):
    """
    Regla 13: COMPRIMIR ARCHIVO
    CREATE(original) + READ + CREATE(comprimido) + SET_INFO(0x13) + WRITE + CLOSE + CLOSE
    Necesita: exactamente 2 FileIDs, SET_INFO(AllocationInfo=0x13).
    """
    if len(fileids) != 2:
        return False
    if len(creates) != 2:
        return False
    # El primer CREATE debe ser de archivo (no directorio)
    first_create = creates[0]
    if _es_directorio(first_create.create_options):
        return False
    # Debe haber SET_INFO(AllocationInfo=0x13)
    info_classes = _info_classes_en_paquetes(paquetes)
    if INFO_CLASS_ALLOCATION_INFO not in info_classes:
        return False
    # Debe haber READ y WRITE
    if "READ" not in comandos or "WRITE" not in comandos:
        return False
    return True


def _es_comprimir_carpeta(paquetes, comandos, fileids, creates):
    """
    Regla 14: COMPRIMIR CARPETA
    CREATE(carpeta) + FIND + (CREATE+READ+CLOSE)*N + CREATE+SET_INFO(0x13)+WRITE+CLOSE
    Necesita: >=3 FileIDs, FIND, READ, WRITE, SET_INFO(AllocationInfo=0x13).
    """
    if len(fileids) < 3:
        return False
    if "QUERY_DIRECTORY" not in comandos:
        return False
    if "READ" not in comandos or "WRITE" not in comandos:
        return False
    info_classes = _info_classes_en_paquetes(paquetes)
    if INFO_CLASS_ALLOCATION_INFO not in info_classes:
        return False
    return True


def _es_modificar_archivo_editor(paquetes, comandos, fileids, creates):
    """
    Regla 15: MODIFICAR ARCHIVO (editor)
    CREATE+READ+CLOSE + CREATE+SET_INFO+WRITE+IOCTL+CLOSE (>=2 FileIDs)
    Necesita: >=2 FileIDs, IOCTL, READ y WRITE.
    """
    if len(fileids) < 2:
        return False
    if "IOCTL" not in comandos:
        return False
    if "READ" not in comandos or "WRITE" not in comandos:
        return False
    return True


def _es_subir_carpeta(paquetes, comandos, fileids, creates):
    """
    Regla 8: SUBIR CARPETA
    CREATE(carpeta) + FIND + (CREATE+WRITE+CLOSE)* + CLOSE
    Necesita: >=2 FileIDs, FIND, WRITE, sin READ.
    """
    if len(fileids) < 2:
        return False
    if "QUERY_DIRECTORY" not in comandos:
        return False
    if "WRITE" not in comandos:
        return False
    if "READ" in comandos:
        return False
    # El primer CREATE debe ser de carpeta
    first_create = creates[0] if creates else None
    if first_create is None or not _es_directorio(first_create.create_options):
        return False
    return True


def _es_bajar_carpeta(paquetes, comandos, fileids, creates):
    """
    Regla 9: BAJAR CARPETA
    CREATE(carpeta) + FIND + (CREATE+READ+CLOSE)* + CLOSE
    Necesita: >=2 FileIDs, FIND, READ, sin WRITE.
    """
    if len(fileids) < 2:
        return False
    if "QUERY_DIRECTORY" not in comandos:
        return False
    if "READ" not in comandos:
        return False
    if "WRITE" in comandos:
        return False
    # El primer CREATE debe ser de carpeta
    first_create = creates[0] if creates else None
    if first_create is None or not _es_directorio(first_create.create_options):
        return False
    return True


def _es_operacion_compleja(paquetes, comandos, fileids, creates):
    """
    Regla 19: OPERACION COMPLEJA (modif+borrar)
    CREATE+READ+WRITE+SET_INFO+CLOSE con >=3 creates.
    """
    if len(creates) < 3:
        return False
    if "READ" not in comandos or "WRITE" not in comandos:
        return False
    if "SET_INFO" not in comandos:
        return False
    return True


def clasificar_operacion_compuesta(op_compuesta):
    """
    Clasifica una operacion compuesta analizando la secuencia completa
    de paquetes. Solo aplica reglas que requieren multiples FileIDs.

    Args:
        op_compuesta: OperacionCompuesta con todos sus paquetes.

    Returns:
        str: Tipo de operacion compuesta, o None si no es compuesta.
    """
    paquetes = op_compuesta.paquetes
    comandos = [p.comando for p in paquetes]
    fileids = set(p.file_id for p in paquetes if p.file_id)
    creates = [p for p in paquetes if p.comando == "CREATE"]

    # Si solo tiene 1 FileID, no es compuesta
    if len(fileids) < 2:
        return None

    # ---- Reglas multi-FileID (de la memoria TFG) ----

    # Regla 12: COPIAR CARPETA
    if _es_copiar_carpeta(paquetes, comandos, fileids, creates):
        return "COPIAR CARPETA"

    # Regla 13: COMPRIMIR ARCHIVO
    if _es_comprimir_archivo(paquetes, comandos, fileids, creates):
        return "COMPRIMIR ARCHIVO"

    # Regla 14: COMPRIMIR CARPETA
    if _es_comprimir_carpeta(paquetes, comandos, fileids, creates):
        return "COMPRIMIR CARPETA"

    # Regla 15: MODIFICAR ARCHIVO (editor)
    if _es_modificar_archivo_editor(paquetes, comandos, fileids, creates):
        return "MODIFICAR ARCHIVO (editor)"

    # Regla 8: SUBIR CARPETA
    if _es_subir_carpeta(paquetes, comandos, fileids, creates):
        return "SUBIR CARPETA"

    # Regla 9: BAJAR CARPETA
    if _es_bajar_carpeta(paquetes, comandos, fileids, creates):
        return "BAJAR CARPETA"

    # Regla 19: OPERACION COMPLEJA (modif+borrar)
    if _es_operacion_compleja(paquetes, comandos, fileids, creates):
        info_classes = _info_classes_en_paquetes(paquetes)
        if INFO_CLASS_BORRAR in info_classes and INFO_CLASS_RENOMBRAR in info_classes:
            return "OPERACION COMPLEJA (modif+borrar+renombrar)"
        if INFO_CLASS_BORRAR in info_classes:
            return "OPERACION COMPLEJA (modif+borrar)"
        if INFO_CLASS_RENOMBRAR in info_classes:
            return "OPERACION COMPLEJA (modif+renombrar)"
        return "OPERACION COMPLEJA (modif masiva)"

    # Si tiene multiples FileIDs pero no coincide con ningun patron
    return "OPERACION COMPLEJA"


# ──────────────────────────────────────────────────────────────────────
# REPORTE V4
# ──────────────────────────────────────────────────────────────────────

def generar_reporte_v4(operaciones_compuestas, solo_resumen=False):
    """Muestra el reporte de operaciones compuestas detectadas."""
    if not solo_resumen:
        print()
        print("=" * 120)
        print("  REPORTE DE OPERACIONES SMB2 (v4) — Simples y Compuestas")
        print("=" * 120)
        print(f"  Total operaciones compuestas: {len(operaciones_compuestas)}")
        print("=" * 120)
        print()

        for i, op_comp in enumerate(operaciones_compuestas, 1):
            tipo = op_comp.tipo_compuesta or op_comp.tipo_atomica or "SIN CLASIFICAR"
            fid_info = f"{op_comp.num_file_ids} FileIDs" if not op_comp.es_simple else "1 FileID"
            simple_comp = "COMPUESTA" if not op_comp.es_simple else "SIMPLE"
            print(f"  | [{i:4d}] [{simple_comp:9s}] {tipo:32s} | {fid_info:14s} | "
                  f"{op_comp.num_paquetes:4d} paqs | "
                  f"{op_comp.duracion_ms:8.2f} ms | "
                  f"Lineas [{op_comp.linea_inicio}--{op_comp.linea_fin}]")

            # Mostrar operaciones atomicas hijas si es compuesta
            if not op_comp.es_simple and op_comp.operaciones_atomicas:
                for j, op_atom in enumerate(op_comp.operaciones_atomicas, 1):
                    print(f"  |         [{j}] {op_atom.resumen()}")
            print()

    # Resumen por tipo (siempre sale, al final)
    conteo_simple = defaultdict(int)
    conteo_compuesto = defaultdict(int)
    conteo_atomico = defaultdict(int)
    for op_comp in operaciones_compuestas:
        if op_comp.es_simple:
            tipo = op_comp.tipo_atomica or "SIN CLASIFICAR"
            conteo_simple[tipo] += 1
            conteo_atomico[tipo] += 1
        else:
            tipo = op_comp.tipo_compuesta or "SIN CLASIFICAR"
            conteo_compuesto[tipo] += 1
            # Contar atomicas hijas
            if op_comp.operaciones_atomicas:
                for op_atom in op_comp.operaciones_atomicas:
                    tipo_atom = op_atom.tipo or "SIN CLASIFICAR"
                    conteo_atomico[tipo_atom] += 1

    print("=" * 120)
    print("  RESUMEN FINAL - OPERACIONES POR TIPO")
    print("=" * 120)

    print("  --- OPERACIONES SIMPLES (1 FileID) ---")
    print("  +-- TIPO DE OPERACION                        TOTAL  -----------+")
    for tipo, num in sorted(conteo_simple.items(), key=lambda x: -x[1]):
        print(f"  | {tipo:40s} -> {num:4d} {'vez' if num == 1 else 'veces'}")
    print()

    print("  --- OPERACIONES COMPUESTAS (multi-FileID) ---")
    print("  +-- TIPO DE OPERACION                        TOTAL  -----------+")
    for tipo, num in sorted(conteo_compuesto.items(), key=lambda x: -x[1]):
        print(f"  | {tipo:40s} -> {num:4d} {'vez' if num == 1 else 'veces'}")
    print()

    total_simples = sum(conteo_simple.values())
    total_compuestas = sum(conteo_compuesto.values())
    total_atomicas = sum(conteo_atomico.values())
    print(f"  Total simples: {total_simples}, Total compuestas: {total_compuestas}")
    print(f"  Total operaciones atomicas extraidas: {total_atomicas}")
    print()
    print("  --- DESGLOSE DE OPERACIONES ATOMICAS (extraidas de simples y compuestas) ---")
    print("  +-- TIPO DE OPERACION                        TOTAL  -----------+")
    for tipo, num in sorted(conteo_atomico.items(), key=lambda x: -x[1]):
        print(f"  | {tipo:40s} -> {num:4d} {'vez' if num == 1 else 'veces'}")
    print()
    print("+---------------------------------------------------------+")
    print()


# ──────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Uso: python src/analizador_smb2_v4.py <archivo.csv> [--resumen] [--debug]")
        print("Ejemplo: python src/analizador_smb2_v4.py Trazas/Traza_user_5.csv")
        print("         python src/analizador_smb2_v4.py Trazas/Traza_user_5.csv --resumen")
        print("         python src/analizador_smb2_v4.py Trazas/Traza_user_5.csv --debug")
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
        print("  ANALIZADOR DE TRAFICO SMB2 (v4)")
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

    # Paso 2: Agrupar por operacion (v4: jerarquia raiz/subordinados)
    if not solo_resumen:
        print()
        print("[2] Agrupando paquetes por operacion (v4: raiz/subordinados)...")
    operaciones_compuestas = agrupar_por_operacion_v4(paquetes)
    if not solo_resumen:
        print(f"  >> {len(operaciones_compuestas)} operaciones compuestas formadas")

    # Paso 3: Para cada operacion compuesta:
    #   3a. Extraer operaciones atomicas hijas
    #   3b. Clasificar cada atomica
    #   3c. Clasificar la compuesta (si tiene multiples FileIDs)
    if not solo_resumen:
        print()
        print("[3] Clasificando operaciones...")
    for op_comp in operaciones_compuestas:
        # 3a. Extraer operaciones atomicas hijas
        op_comp.operaciones_atomicas = extraer_operaciones_atomicas(op_comp)

        # 3b. Clasificar cada atomica
        for op_atom in op_comp.operaciones_atomicas:
            op_atom.tipo = clasificar_operacion(op_atom)

        # 3c. Clasificar la compuesta
        if not op_comp.es_simple:
            op_comp.tipo_compuesta = clasificar_operacion_compuesta(op_comp)
            if modo_debug and op_comp.tipo_compuesta == "OPERACION COMPLEJA":
                print(f"  [DEBUG] Compuesta sin patron: {op_comp.num_file_ids} FileIDs, "
                      f"{op_comp.num_paquetes} paquetes, "
                      f"Lineas [{op_comp.linea_inicio}--{op_comp.linea_fin}]")
        else:
            # Si es simple, usar la clasificacion de su unica atomica
            if op_comp.operaciones_atomicas:
                op_comp.tipo_atomica = op_comp.operaciones_atomicas[0].tipo

    if not solo_resumen:
        print("  >> Clasificacion completada")

    # Paso 4: Reporte
    if not solo_resumen:
        print()
        print("[4] Generando reporte...")
    generar_reporte_v4(operaciones_compuestas, solo_resumen=solo_resumen)

    if not solo_resumen:
        print()
        print("[*] Analisis completado.")
        print()


if __name__ == "__main__":
    main()