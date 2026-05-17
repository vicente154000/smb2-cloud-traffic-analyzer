# -*- coding: utf-8 -*-
"""
Fixtures compartidos para los tests del analizador SMB2.
Proporciona datos de prueba reutilizables: paquetes, operaciones, CSV.
"""

import sys
import os
import csv
import io
import tempfile

# Añadir src/ al path para poder importar los modulos
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from analizador_smb2_v2 import (
    PaqueteSMB2, Operacion,
    leer_csv, agrupar_por_operacion, clasificar_operacion,
    INFO_CLASS_BORRAR, INFO_CLASS_RENOMBRAR,
    INFO_CLASS_ALLOCATION_INFO, INFO_CLASS_END_OF_FILE_INFO,
    CREATE_OPTIONS_DIRECTORIO,
)


# =========================================================================
# FIXTURES: Paquetes SMB2 individuales
# =========================================================================

@pytest.fixture
def pkt_create_archivo():
    """CREATE de un archivo normal (sin bit directorio)."""
    return PaqueteSMB2(
        linea=100, comando="CREATE", timestamp=1.0,
        tree_id=1, file_id="FID001", file_path="ruta/documento.pdf",
        create_options=0x20, info_class=None,
        read_len=None, write_len=None,
        read_offset=None, write_offset=None,
        tiene_error=False,
    )


@pytest.fixture
def pkt_create_directorio():
    """CREATE de un directorio (con bit 0x01)."""
    return PaqueteSMB2(
        linea=100, comando="CREATE", timestamp=1.0,
        tree_id=1, file_id="FID002", file_path="ruta/carpeta",
        create_options=0x01, info_class=None,
        read_len=None, write_len=None,
        read_offset=None, write_offset=None,
        tiene_error=False,
    )


@pytest.fixture
def pkt_read():
    """READ de 4096 bytes."""
    return PaqueteSMB2(
        linea=101, comando="READ", timestamp=1.1,
        tree_id=1, file_id="FID001", file_path=None,
        create_options=None, info_class=None,
        read_len=4096, write_len=None,
        read_offset=0, write_offset=None,
        tiene_error=False,
    )


@pytest.fixture
def pkt_write():
    """WRITE de 8192 bytes."""
    return PaqueteSMB2(
        linea=102, comando="WRITE", timestamp=1.2,
        tree_id=1, file_id="FID001", file_path=None,
        create_options=None, info_class=None,
        read_len=None, write_len=8192,
        read_offset=None, write_offset=0,
        tiene_error=False,
    )


@pytest.fixture
def pkt_close():
    """CLOSE."""
    return PaqueteSMB2(
        linea=103, comando="CLOSE", timestamp=1.3,
        tree_id=1, file_id="FID001", file_path=None,
        create_options=None, info_class=None,
        read_len=None, write_len=None,
        read_offset=None, write_offset=None,
        tiene_error=False,
    )


@pytest.fixture
def pkt_setinfo_borrar():
    """SET_INFO con InfoClass=0x0D (FileDispositionInformation = borrar)."""
    return PaqueteSMB2(
        linea=104, comando="SET_INFO", timestamp=1.15,
        tree_id=1, file_id="FID001", file_path=None,
        create_options=None, info_class=INFO_CLASS_BORRAR,
        read_len=None, write_len=None,
        read_offset=None, write_offset=None,
        tiene_error=False,
    )


@pytest.fixture
def pkt_setinfo_renombrar():
    """SET_INFO con InfoClass=0x0A (FileRenameInformation = renombrar)."""
    return PaqueteSMB2(
        linea=105, comando="SET_INFO", timestamp=1.15,
        tree_id=1, file_id="FID001", file_path=None,
        create_options=None, info_class=INFO_CLASS_RENOMBRAR,
        read_len=None, write_len=None,
        read_offset=None, write_offset=None,
        tiene_error=False,
    )


@pytest.fixture
def pkt_query_directory():
    """QUERY_DIRECTORY (listar directorio)."""
    return PaqueteSMB2(
        linea=106, comando="QUERY_DIRECTORY", timestamp=1.0,
        tree_id=1, file_id=None, file_path=None,
        create_options=None, info_class=None,
        read_len=None, write_len=None,
        read_offset=None, write_offset=None,
        tiene_error=False,
    )


@pytest.fixture
def pkt_query_info():
    """QUERY_INFO (consultar metadatos)."""
    return PaqueteSMB2(
        linea=107, comando="QUERY_INFO", timestamp=1.0,
        tree_id=1, file_id=None, file_path=None,
        create_options=None, info_class=None,
        read_len=None, write_len=None,
        read_offset=None, write_offset=None,
        tiene_error=False,
    )


# =========================================================================
# FIXTURES: Operaciones completas (grupos de paquetes)
# =========================================================================

@pytest.fixture
def op_subir_archivo(pkt_create_archivo, pkt_write, pkt_close):
    """Operacion: SUBIR ARCHIVO (CREATE + WRITE + CLOSE)."""
    op = Operacion()
    op.anyadir(pkt_create_archivo)
    op.anyadir(pkt_write)
    op.anyadir(pkt_close)
    return op


@pytest.fixture
def op_bajar_archivo(pkt_create_archivo, pkt_read, pkt_close):
    """Operacion: BAJAR ARCHIVO (CREATE + READ + CLOSE)."""
    op = Operacion()
    op.anyadir(pkt_create_archivo)
    op.anyadir(pkt_read)
    op.anyadir(pkt_close)
    return op


@pytest.fixture
def op_borrar_archivo(pkt_create_archivo, pkt_setinfo_borrar, pkt_close):
    """Operacion: BORRAR ARCHIVO (CREATE + SET_INFO(0x0D) + CLOSE)."""
    op = Operacion()
    op.anyadir(pkt_create_archivo)
    op.anyadir(pkt_setinfo_borrar)
    op.anyadir(pkt_close)
    return op


@pytest.fixture
def op_renombrar_archivo(pkt_create_archivo, pkt_setinfo_renombrar, pkt_close):
    """Operacion: RENOMBRAR/MOVER ARCHIVO (CREATE + SET_INFO(0x0A) + CLOSE)."""
    op = Operacion()
    op.anyadir(pkt_create_archivo)
    op.anyadir(pkt_setinfo_renombrar)
    op.anyadir(pkt_close)
    return op


@pytest.fixture
def op_crear_carpeta(pkt_create_directorio, pkt_close):
    """Operacion: CREAR CARPETA (CREATE con bit directorio + CLOSE)."""
    op = Operacion()
    op.anyadir(pkt_create_directorio)
    op.anyadir(pkt_close)
    return op


@pytest.fixture
def op_crear_archivo_vacio(pkt_create_archivo, pkt_close):
    """Operacion: CREAR ARCHIVO VACIO (CREATE sin bit dir + CLOSE, sin E/S)."""
    op = Operacion()
    op.anyadir(pkt_create_archivo)
    op.anyadir(pkt_close)
    return op


@pytest.fixture
def op_listar_directorio(pkt_query_directory):
    """Operacion: LISTAR DIRECTORIO (solo QUERY_DIRECTORY)."""
    op = Operacion()
    op.anyadir(pkt_query_directory)
    return op


@pytest.fixture
def op_consultar_metadatos(pkt_query_info):
    """Operacion: CONSULTAR METADATOS (solo QUERY_INFO)."""
    op = Operacion()
    op.anyadir(pkt_query_info)
    return op


@pytest.fixture
def op_create_sin_close(pkt_create_archivo):
    """Operacion: CREATE sin CLOSE (deberia ser DESCONOCIDA)."""
    op = Operacion()
    op.anyadir(pkt_create_archivo)
    return op


# =========================================================================
# FIXTURES: Datos CSV de prueba (en memoria)
# =========================================================================

def _escribir_csv_temp(filas):
    """
    Crea un archivo CSV temporal con cabeceras estilo Wireshark
    y las filas de datos proporcionadas.
    
    Args:
        filas: lista de listas, cada una es una fila del CSV (20 columnas)
    
    Returns:
        ruta del archivo temporal
    """
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".csv",
                                    encoding="utf-8-sig", delete=False)
    writer = csv.writer(f)
    # Cabeceras (filas 1-14)
    writer.writerow(["Client IP", "Client Port", "Server IP", "Server Port",
                     "TCP Connection Id", "Timestamp comienzo(REQ)",
                     "", "", "", "SMB2 command name", "HayError?",
                     "", "", "Tree id", "", "", "", "", "", ""])
    for _ in range(13):
        writer.writerow([""] * 20)
    writer.writerow([""] * 20)  # fila 15
    writer.writerow([""] * 20)  # fila 16
    # Datos
    for fila in filas:
        # Rellenar hasta 20 columnas
        fila_completa = list(fila) + [""] * (20 - len(fila))
        writer.writerow(fila_completa[:20])
    f.close()
    return f.name


@pytest.fixture
def csv_subir_archivo():
    """CSV con una operacion de subida: CREATE + WRITE + CLOSE."""
    filas = [
        ["", "", "", "", "", "1.000", "", "", "", "CREATE", "0",
         "", "", "1", "FID001", "0x60", "", "", "", "ruta/doc.pdf"],
        ["", "", "", "", "", "1.100", "", "", "", "WRITE", "0",
         "", "", "1", "FID001", "8192", "", "0", "", ""],
        ["", "", "", "", "", "1.200", "", "", "", "CLOSE", "0",
         "", "", "1", "FID001", "", "", "", "", ""],
    ]
    ruta = _escribir_csv_temp(filas)
    yield ruta
    os.unlink(ruta)


@pytest.fixture
def csv_borrar_archivo():
    """CSV con una operacion de borrado: CREATE + SET_INFO(0x0D) + CLOSE."""
    filas = [
        ["", "", "", "", "", "2.000", "", "", "", "CREATE", "0",
         "", "", "1", "FID002", "0x60", "", "", "", "ruta/doc.pdf"],
        ["", "", "", "", "", "2.050", "", "", "", "SET_INFO", "0",
         "", "", "1", "FID002", "", "13", "", "", ""],
        ["", "", "", "", "", "2.100", "", "", "", "CLOSE", "0",
         "", "", "1", "FID002", "", "", "", "", ""],
    ]
    ruta = _escribir_csv_temp(filas)
    yield ruta
    os.unlink(ruta)


@pytest.fixture
def csv_crear_carpeta():
    """CSV con creacion de carpeta: CREATE(bit dir) + CLOSE."""
    filas = [
        ["", "", "", "", "", "3.000", "", "", "", "CREATE", "0",
         "", "", "1", "FID003", "33", "", "", "", "ruta/nueva"],
        ["", "", "", "", "", "3.100", "", "", "", "CLOSE", "0",
         "", "", "1", "FID003", "", "", "", "", ""],
    ]
    ruta = _escribir_csv_temp(filas)
    yield ruta
    os.unlink(ruta)


@pytest.fixture
def csv_operaciones_multiples():
    """
    CSV con 3 operaciones distintas en el mismo FileID:
    1. CREATE + WRITE + CLOSE (subir)
    2. CREATE + READ + CLOSE (bajar)
    3. CREATE + SET_INFO(0x0D) + CLOSE (borrar)
    """
    filas = [
        # Op1: SUBIR ARCHIVO
        ["", "", "", "", "", "10.000", "", "", "", "CREATE", "0",
         "", "", "1", "FID100", "0x60", "", "", "", "ruta/a.pdf"],
        ["", "", "", "", "", "10.100", "", "", "", "WRITE", "0",
         "", "", "1", "FID100", "4096", "", "0", "", ""],
        ["", "", "", "", "", "10.200", "", "", "", "CLOSE", "0",
         "", "", "1", "FID100", "", "", "", "", ""],
        # Op2: BAJAR ARCHIVO
        ["", "", "", "", "", "20.000", "", "", "", "CREATE", "0",
         "", "", "1", "FID101", "0x60", "", "", "", "ruta/b.pdf"],
        ["", "", "", "", "", "20.100", "", "", "", "READ", "0",
         "", "", "1", "FID101", "8192", "", "0", "", ""],
        ["", "", "", "", "", "20.200", "", "", "", "CLOSE", "0",
         "", "", "1", "FID101", "", "", "", "", ""],
        # Op3: BORRAR ARCHIVO
        ["", "", "", "", "", "30.000", "", "", "", "CREATE", "0",
         "", "", "1", "FID102", "0x60", "", "", "", "ruta/c.pdf"],
        ["", "", "", "", "", "30.050", "", "", "", "SET_INFO", "0",
         "", "", "1", "FID102", "", "13", "", "", ""],
        ["", "", "", "", "", "30.100", "", "", "", "CLOSE", "0",
         "", "", "1", "FID102", "", "", "", "", ""],
    ]
    ruta = _escribir_csv_temp(filas)
    yield ruta
    os.unlink(ruta)


@pytest.fixture
def csv_con_ruido():
    """
    CSV con operaciones mezcladas con ruido (NEGOTIATE, SESSION_SETUP).
    El ruido debe ser filtrado.
    """
    filas = [
        # Ruido
        ["", "", "", "", "", "0.000", "", "", "", "NEGOTIATE", "0",
         "", "", "", "", "", "", "", "", ""],
        ["", "", "", "", "", "0.001", "", "", "", "SESSION_SETUP", "0",
         "", "", "", "", "", "", "", "", ""],
        # Operacion real
        ["", "", "", "", "", "1.000", "", "", "", "CREATE", "0",
         "", "", "1", "FID200", "0x60", "", "", "", "ruta/doc.pdf"],
        ["", "", "", "", "", "1.100", "", "", "", "WRITE", "0",
         "", "", "1", "FID200", "4096", "", "0", "", ""],
        ["", "", "", "", "", "1.200", "", "", "", "CLOSE", "0",
         "", "", "1", "FID200", "", "", "", "", ""],
        # Mas ruido
        ["", "", "", "", "", "2.000", "", "", "", "TREE_CONNECT", "0",
         "", "", "", "", "", "", "", "", ""],
        ["", "", "", "", "", "2.001", "", "", "", "ECHO", "0",
         "", "", "", "", "", "", "", "", ""],
    ]
    ruta = _escribir_csv_temp(filas)
    yield ruta
    os.unlink(ruta)


@pytest.fixture
def csv_create_sin_close():
    """
    CSV con un CREATE que no tiene CLOSE (debe ser DESCONOCIDA).
    """
    filas = [
        ["", "", "", "", "", "1.000", "", "", "", "CREATE", "0",
         "", "", "1", "FID300", "0x60", "", "", "", "ruta/huerfano.pdf"],
        # Nota: no hay CLOSE para FID300
    ]
    ruta = _escribir_csv_temp(filas)
    yield ruta
    os.unlink(ruta)


@pytest.fixture
def csv_async_noise():
    """
    CSV con paquetes entre CLOSE y siguiente CREATE que deben descartarse.
    CREATE + WRITE + CLOSE + (paquetes basura) + CREATE + WRITE + CLOSE
    """
    filas = [
        # Op1
        ["", "", "", "", "", "1.000", "", "", "", "CREATE", "0",
         "", "", "1", "FID400", "0x60", "", "", "", "ruta/op1.pdf"],
        ["", "", "", "", "", "1.100", "", "", "", "WRITE", "0",
         "", "", "1", "FID400", "4096", "", "0", "", ""],
        ["", "", "", "", "", "1.200", "", "", "", "CLOSE", "0",
         "", "", "1", "FID400", "", "", "", "", ""],
        # Paquetes basura entre CLOSE y siguiente CREATE (deben descartarse)
        ["", "", "", "", "", "1.300", "", "", "", "READ", "0",
         "", "", "1", "FID400", "4096", "", "0", "", ""],
        ["", "", "", "", "", "1.400", "", "", "", "WRITE", "0",
         "", "", "1", "FID400", "8192", "", "0", "", ""],
        # Op2
        ["", "", "", "", "", "2.000", "", "", "", "CREATE", "0",
         "", "", "1", "FID400", "0x60", "", "", "", "ruta/op2.pdf"],
        ["", "", "", "", "", "2.100", "", "", "", "WRITE", "0",
         "", "", "1", "FID400", "8192", "", "0", "", ""],
        ["", "", "", "", "", "2.200", "", "", "", "CLOSE", "0",
         "", "", "1", "FID400", "", "", "", "", ""],
    ]
    ruta = _escribir_csv_temp(filas)
    yield ruta
    os.unlink(ruta)
