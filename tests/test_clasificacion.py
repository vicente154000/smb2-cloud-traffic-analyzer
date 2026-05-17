# -*- coding: utf-8 -*-
"""
Tests de componente para la clasificacion de operaciones SMB2.

Cada test verifica que una operacion (grupo de paquetes) se clasifica
correctamente segun las reglas definidas en la memoria TFG.

Ejecucion:
    pytest tests/test_clasificacion.py -v
    pytest tests/test_clasificacion.py -v --tb=short
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from analizador_smb2_v2 import (
    PaqueteSMB2, Operacion, clasificar_operacion,
    _es_directorio, _info_classes_en_operacion,
    INFO_CLASS_BORRAR, INFO_CLASS_RENOMBRAR,
    INFO_CLASS_ALLOCATION_INFO, INFO_CLASS_END_OF_FILE_INFO,
)


# =========================================================================
# TESTS: Reglas basicas de clasificacion
# =========================================================================

class TestClasificacionSubirArchivo:
    """Regla 6: CREATE + WRITE* + CLOSE (sin READ)."""

    def test_subir_archivo_simple(self, op_subir_archivo):
        """CREATE + 1 WRITE + CLOSE -> SUBIR ARCHIVO."""
        assert clasificar_operacion(op_subir_archivo) == "SUBIR ARCHIVO"

    def test_subir_archivo_multiples_writes(self, pkt_create_archivo, pkt_close):
        """CREATE + 3 WRITEs + CLOSE -> SUBIR ARCHIVO."""
        op = Operacion()
        op.anyadir(pkt_create_archivo)
        for i in range(3):
            op.anyadir(PaqueteSMB2(
                linea=200 + i, comando="WRITE", timestamp=1.1 + i * 0.1,
                tree_id=1, file_id="FID001", file_path=None,
                create_options=None, info_class=None,
                read_len=None, write_len=4096,
                read_offset=None, write_offset=i * 4096,
                tiene_error=False,
            ))
        op.anyadir(pkt_close)
        assert clasificar_operacion(op) == "SUBIR ARCHIVO"

    def test_subir_archivo_con_setinfo_no_borrar(self, pkt_create_archivo, pkt_write, pkt_close):
        """CREATE + SET_INFO(0x04) + WRITE + CLOSE -> SUBIR ARCHIVO (regla 6 coincide antes que regla 10)."""
        op = Operacion()
        op.anyadir(pkt_create_archivo)
        op.anyadir(PaqueteSMB2(
            linea=150, comando="SET_INFO", timestamp=1.05,
            tree_id=1, file_id="FID001", file_path=None,
            create_options=None, info_class=0x04,  # FileBasicInfo
            read_len=None, write_len=None,
            read_offset=None, write_offset=None,
            tiene_error=False,
        ))
        op.anyadir(pkt_write)
        op.anyadir(pkt_close)
        # Regla 6 (SUBIR ARCHIVO) solo comprueba CREATE+WRITE+CLOSE+sinREAD+sinFIND
        # No comprueba SET_INFO, por lo que coincide antes que regla 10 (COPIAR ARCHIVO)
        assert clasificar_operacion(op) == "SUBIR ARCHIVO"


class TestClasificacionBajarArchivo:
    """Regla 7: CREATE + READ* + CLOSE (sin WRITE)."""

    def test_bajar_archivo_simple(self, op_bajar_archivo):
        """CREATE + 1 READ + CLOSE -> BAJAR ARCHIVO."""
        assert clasificar_operacion(op_bajar_archivo) == "BAJAR ARCHIVO"

    def test_bajar_archivo_multiples_reads(self, pkt_create_archivo, pkt_close):
        """CREATE + 5 READs + CLOSE -> BAJAR ARCHIVO."""
        op = Operacion()
        op.anyadir(pkt_create_archivo)
        for i in range(5):
            op.anyadir(PaqueteSMB2(
                linea=200 + i, comando="READ", timestamp=1.1 + i * 0.1,
                tree_id=1, file_id="FID001", file_path=None,
                create_options=None, info_class=None,
                read_len=8192, write_len=None,
                read_offset=i * 8192, write_offset=None,
                tiene_error=False,
            ))
        op.anyadir(pkt_close)
        assert clasificar_operacion(op) == "BAJAR ARCHIVO"


class TestClasificacionBorrar:
    """Regla 4: CREATE + SET_INFO(0x0D) + CLOSE."""

    def test_borrar_archivo(self, op_borrar_archivo):
        """CREATE + SET_INFO(0x0D) + CLOSE -> BORRAR ARCHIVO."""
        assert clasificar_operacion(op_borrar_archivo) == "BORRAR ARCHIVO"

    def test_borrar_carpeta(self, pkt_create_directorio, pkt_setinfo_borrar, pkt_close):
        """CREATE(dir) + SET_INFO(0x0D) + CLOSE -> BORRAR CARPETA."""
        op = Operacion()
        op.anyadir(pkt_create_directorio)
        op.anyadir(pkt_setinfo_borrar)
        op.anyadir(pkt_close)
        assert clasificar_operacion(op) == "BORRAR CARPETA"


class TestClasificacionRenombrar:
    """Regla 5: CREATE + SET_INFO(0x0A) + CLOSE."""

    def test_renombrar_archivo(self, op_renombrar_archivo):
        """CREATE + SET_INFO(0x0A) + CLOSE -> RENOMBRAR/MOVER ARCHIVO."""
        assert clasificar_operacion(op_renombrar_archivo) == "RENOMBRAR/MOVER ARCHIVO"

    def test_renombrar_carpeta(self, pkt_create_directorio, pkt_setinfo_renombrar, pkt_close):
        """CREATE(dir) + SET_INFO(0x0A) + CLOSE -> RENOMBRAR/MOVER CARPETA."""
        op = Operacion()
        op.anyadir(pkt_create_directorio)
        op.anyadir(pkt_setinfo_renombrar)
        op.anyadir(pkt_close)
        assert clasificar_operacion(op) == "RENOMBRAR/MOVER CARPETA"


class TestClasificacionCrearCarpeta:
    """Regla 2: CREATE(bit directorio) + CLOSE (sin E/S)."""

    def test_crear_carpeta(self, op_crear_carpeta):
        """CREATE(dir) + CLOSE -> CREAR CARPETA."""
        assert clasificar_operacion(op_crear_carpeta) == "CREAR CARPETA"


class TestClasificacionCrearArchivoVacio:
    """Regla 3: CREATE(sin bit dir) + CLOSE (sin E/S, sin SET_INFO)."""

    def test_crear_archivo_vacio(self, op_crear_archivo_vacio):
        """CREATE + CLOSE (sin E/S) -> CREAR ARCHIVO VACIO."""
        assert clasificar_operacion(op_crear_archivo_vacio) == "CREAR ARCHIVO VACIO"


class TestClasificacionListarDirectorio:
    """Regla 1: CREATE + FIND* + CLOSE."""

    def test_listar_directorio(self, pkt_create_archivo, pkt_query_directory, pkt_close):
        """CREATE + FIND + CLOSE -> LISTAR DIRECTORIO."""
        op = Operacion()
        op.anyadir(pkt_create_archivo)
        op.anyadir(pkt_query_directory)
        op.anyadir(pkt_close)
        assert clasificar_operacion(op) == "LISTAR DIRECTORIO"

    def test_solo_query_directory(self, op_listar_directorio):
        """Solo QUERY_DIRECTORY (sin CREATE/CLOSE) -> DESCONOCIDA."""
        # Regla 1 requiere CREATE+FIND+CLOSE; solo QUERY_DIRECTORY cae en DESCONOCIDA
        assert clasificar_operacion(op_listar_directorio) == "DESCONOCIDA"


class TestClasificacionConsultarMetadatos:
    """Regla 17: Solo QUERY_INFO."""

    def test_consultar_metadatos(self, op_consultar_metadatos):
        """Solo QUERY_INFO -> CONSULTAR METADATOS."""
        assert clasificar_operacion(op_consultar_metadatos) == "CONSULTAR METADATOS"


# =========================================================================
# TESTS: Casos especiales y bordes
# =========================================================================

class TestClasificacionCasosEspeciales:

    def test_create_sin_close(self, op_create_sin_close):
        """CREATE sin CLOSE -> DESCONOCIDA (regla 18 requiere CLOSE)."""
        # Regla 18 (APERTURA EFIMERA) requiere tiene_close=True
        # Solo CREATE sin CLOSE no coincide con ninguna regla -> DESCONOCIDA
        resultado = clasificar_operacion(op_create_sin_close)
        assert resultado == "DESCONOCIDA"

    def test_solo_close(self, pkt_close):
        """Solo CLOSE (sin CREATE) -> RUIDO/SIN OPERACION."""
        op = Operacion()
        op.anyadir(pkt_close)
        assert clasificar_operacion(op) == "RUIDO/SIN OPERACION"

    def test_solo_read(self, pkt_read):
        """Solo READ (sin CREATE) -> DESCONOCIDA (regla 20 requiere no tiene_read)."""
        op = Operacion()
        op.anyadir(pkt_read)
        # Regla 20: not tiene_create AND not tiene_read AND not tiene_write AND not tiene_find
        # Solo READ tiene tiene_read=True -> no coincide -> DESCONOCIDA
        assert clasificar_operacion(op) == "DESCONOCIDA"

    def test_solo_write(self, pkt_write):
        """Solo WRITE (sin CREATE) -> DESCONOCIDA (regla 20 requiere no tiene_write)."""
        op = Operacion()
        op.anyadir(pkt_write)
        assert clasificar_operacion(op) == "DESCONOCIDA"

    def test_operacion_vacia(self):
        """Operacion sin paquetes -> RUIDO/SIN OPERACION."""
        op = Operacion()
        assert clasificar_operacion(op) == "RUIDO/SIN OPERACION"

    def test_create_con_error(self, pkt_create_archivo, pkt_close):
        """CREATE con error + CLOSE -> CREAR ARCHIVO VACIO (regla 3 coincide antes que regla 18)."""
        pkt_con_error = PaqueteSMB2(
            linea=100, comando="CREATE", timestamp=1.0,
            tree_id=1, file_id="FID001", file_path="ruta/doc.pdf",
            create_options=0x20, info_class=None,
            read_len=None, write_len=None,
            read_offset=None, write_offset=None,
            tiene_error=True,
        )
        op = Operacion()
        op.anyadir(pkt_con_error)
        op.anyadir(pkt_close)
        # Regla 3 (CREAR ARCHIVO VACIO): CREATE+CLOSE sin E/S/SET_INFO/FIND
        # Coincide antes que regla 18 (APERTURA EFIMERA)
        assert clasificar_operacion(op) == "CREAR ARCHIVO VACIO"


class TestClasificacionOperacionesComplejas:

    def test_modificar_archivo_editor(self, pkt_create_archivo, pkt_read, pkt_write, pkt_close):
        """
        Regla 15: MODIFICAR ARCHIVO (editor).
        CREATE + READ + WRITE + IOCTL + CLOSE con >= 2 FileIDs.
        """
        op = Operacion()
        op.anyadir(pkt_create_archivo)
        op.anyadir(pkt_read)
        op.anyadir(PaqueteSMB2(
            linea=150, comando="IOCTL", timestamp=1.15,
            tree_id=1, file_id="FID002", file_path=None,
            create_options=None, info_class=None,
            read_len=None, write_len=None,
            read_offset=None, write_offset=None,
            tiene_error=False,
        ))
        op.anyadir(pkt_write)
        op.anyadir(pkt_close)
        # Necesita >= 2 FileIDs diferentes
        # pkt_create_archivo tiene FID001, el IOCTL tiene FID002
        assert clasificar_operacion(op) == "MODIFICAR ARCHIVO (editor)"

    def test_comprimir_archivo(self, pkt_create_archivo, pkt_read, pkt_write, pkt_close):
        """
        Regla 13: COMPRIMIR ARCHIVO.
        READ + CREATE + SET_INFO(AllocationInfo) + WRITE + CLOSE con >= 2 FileIDs.
        """
        op = Operacion()
        # READ de otro FileID (lectura del original)
        op.anyadir(PaqueteSMB2(
            linea=100, comando="READ", timestamp=1.0,
            tree_id=1, file_id="FID_ORIG", file_path=None,
            create_options=None, info_class=None,
            read_len=4096, write_len=None,
            read_offset=0, write_offset=None,
            tiene_error=False,
        ))
        op.anyadir(pkt_create_archivo)
        op.anyadir(PaqueteSMB2(
            linea=102, comando="SET_INFO", timestamp=1.1,
            tree_id=1, file_id="FID001", file_path=None,
            create_options=None, info_class=INFO_CLASS_ALLOCATION_INFO,
            read_len=None, write_len=None,
            read_offset=None, write_offset=None,
            tiene_error=False,
        ))
        op.anyadir(pkt_write)
        op.anyadir(pkt_close)
        assert clasificar_operacion(op) == "COMPRIMIR ARCHIVO"

    def test_operacion_compleja_modif_borrar(self, pkt_create_archivo, pkt_read, pkt_write, pkt_close):
        """
        Regla 19: OPERACION COMPLEJA (modif+borrar).
        CREATE + READ + WRITE + SET_INFO(0x0D) + CLOSE con >= 3 creates.
        """
        op = Operacion()
        op.anyadir(pkt_create_archivo)
        op.anyadir(PaqueteSMB2(
            linea=101, comando="CREATE", timestamp=1.05,
            tree_id=1, file_id="FID002", file_path=None,
            create_options=0x20, info_class=None,
            read_len=None, write_len=None,
            read_offset=None, write_offset=None,
            tiene_error=False,
        ))
        op.anyadir(PaqueteSMB2(
            linea=102, comando="CREATE", timestamp=1.06,
            tree_id=1, file_id="FID003", file_path=None,
            create_options=0x20, info_class=None,
            read_len=None, write_len=None,
            read_offset=None, write_offset=None,
            tiene_error=False,
        ))
        op.anyadir(pkt_read)
        op.anyadir(pkt_write)
        op.anyadir(PaqueteSMB2(
            linea=105, comando="SET_INFO", timestamp=1.15,
            tree_id=1, file_id="FID001", file_path=None,
            create_options=None, info_class=INFO_CLASS_BORRAR,
            read_len=None, write_len=None,
            read_offset=None, write_offset=None,
            tiene_error=False,
        ))
        op.anyadir(pkt_close)
        assert clasificar_operacion(op) == "OPERACION COMPLEJA (modif+borrar)"


# =========================================================================
# TESTS: Funciones auxiliares
# =========================================================================

class TestFuncionesAuxiliares:

    def test_es_directorio_true(self):
        """CreateOptions con bit 0x01 -> es directorio."""
        assert _es_directorio(0x01)  # truthy
        assert _es_directorio(0x21)  # 0x20 | 0x01
        assert _es_directorio(0x100001)

    def test_es_directorio_false(self):
        """CreateOptions sin bit 0x01 -> no es directorio."""
        assert not _es_directorio(0x20)
        assert not _es_directorio(0x60)
        assert not _es_directorio(0x100)
        assert not _es_directorio(None)

    def test_info_classes_en_operacion(self, op_borrar_archivo):
        """SET_INFO(0x0D) debe aparecer en info_classes."""
        clases = _info_classes_en_operacion(op_borrar_archivo)
        assert INFO_CLASS_BORRAR in clases
        assert INFO_CLASS_RENOMBRAR not in clases

    def test_info_classes_vacio(self, op_subir_archivo):
        """Operacion sin SET_INFO -> conjunto vacio."""
        clases = _info_classes_en_operacion(op_subir_archivo)
        assert len(clases) == 0


# =========================================================================
# TESTS: Prioridad de reglas (orden matters)
# =========================================================================

class TestPrioridadReglas:

    def test_create_dir_con_find(self, pkt_create_directorio, pkt_close, pkt_query_directory):
        """
        CREATE(dir) + FIND + CLOSE -> LISTAR DIRECTORIO (regla 1 coincide antes que regla 2).
        Regla 1 (LISTAR DIRECTORIO): CREATE+FIND+CLOSE (sin READ/WRITE/SET_INFO)
        Regla 2 (CREAR CARPETA): CREATE(dir)+CLOSE (sin READ/WRITE/SET_INFO)
        Regla 1 es mas especifica y esta antes, por eso LISTAR DIRECTORIO gana.
        """
        op = Operacion()
        op.anyadir(pkt_create_directorio)
        op.anyadir(pkt_query_directory)
        op.anyadir(pkt_close)
        assert clasificar_operacion(op) == "LISTAR DIRECTORIO"

    def test_create_con_setinfo_borrar_y_find(self, pkt_create_archivo, pkt_setinfo_borrar,
                                               pkt_close, pkt_query_directory):
        """
        CREATE + SET_INFO(0x0D) + FIND + CLOSE -> BORRAR ARCHIVO (regla 4)
        El SET_INFO de borrado tiene prioridad sobre FIND.
        """
        op = Operacion()
        op.anyadir(pkt_create_archivo)
        op.anyadir(pkt_setinfo_borrar)
        op.anyadir(pkt_query_directory)
        op.anyadir(pkt_close)
        assert clasificar_operacion(op) == "BORRAR ARCHIVO"

    def test_create_read_write(self, pkt_create_archivo, pkt_read, pkt_write, pkt_close):
        """
        CREATE + READ + WRITE + CLOSE -> debe caer en alguna regla.
        Sin IOCTL ni SET_INFO ni FileIDs >= 2 -> DESCONOCIDA (no hay regla exacta).
        """
        op = Operacion()
        op.anyadir(pkt_create_archivo)
        op.anyadir(pkt_read)
        op.anyadir(pkt_write)
        op.anyadir(pkt_close)
        # Solo 1 FileID, sin IOCTL, sin SET_INFO -> no coincide con MODIFICAR ni COMPRIMIR
        assert clasificar_operacion(op) == "DESCONOCIDA"
