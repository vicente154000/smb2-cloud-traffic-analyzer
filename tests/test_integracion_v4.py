# -*- coding: utf-8 -*-
"""
Tests de integracion para el pipeline v4 del analizador SMB2.

Verifica componentes ORTOGONALES del pipeline v4 que NO estan cubiertos
por los validators (validar_todas_operaciones.py y validar_pipeline_v4.py):

1. _pre_escanear_fids_con_close() -> pre-escaneo de FileIDs con CLOSE
2. agrupar_por_operacion_v4() -> agrupacion jerarquica (casos unicos)
3. extraer_operaciones_atomicas() -> separacion por FileID
4. clasificar_operacion_compuesta() -> clasificacion de compuestas
5. generar_reporte_v4() -> reporte final
6. leer_csv() con traza real -> integracion real

NO incluye (cubierto por validators):
- TestClasificacionAtomicasV4 -> cubierto por validar_todas_operaciones.py (23 casos)
- TestPipelineCompletoV4 -> cubierto por validar_pipeline_v4.py (7 casos entremezclados)
- Tests de agrupacion duplicados con validar_pipeline_v4.py

Ejecucion:
    pytest tests/test_integracion_v4.py -v
    pytest tests/test_integracion_v4.py -v --tb=short
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))  # para importar helpers

import pytest
from analizador_smb2_v4 import (
    PaqueteSMB2, Operacion, OperacionCompuesta,
    leer_csv, agrupar_por_operacion_v4,
    extraer_operaciones_atomicas,
    clasificar_operacion, clasificar_operacion_compuesta,
    generar_reporte_v4,
    _pre_escanear_fids_con_close,
    INFO_CLASS_BORRAR, INFO_CLASS_RENOMBRAR,
    INFO_CLASS_ALLOCATION_INFO,
    CREATE_OPTIONS_DIRECTORIO,
)
from helpers import pkt


# =========================================================================
# TESTS: Pre-escaneo de FileIDs con CLOSE (NO cubierto por validators)
# =========================================================================

class TestPreEscaneo:

    def test_fids_con_close_detectados(self):
        """Pre-escaneo debe detectar FileIDs que tienen CLOSE."""
        paquetes = [
            pkt("CREATE", file_id="FID_A", timestamp=1.0),
            pkt("READ", file_id="FID_A", timestamp=1.1),
            pkt("CLOSE", file_id="FID_A", timestamp=1.2),
            pkt("CREATE", file_id="FID_B", timestamp=2.0),
            # FID_B no tiene CLOSE
        ]
        fids = _pre_escanear_fids_con_close(paquetes)
        assert "FID_A" in fids
        assert "FID_B" not in fids

    def test_fids_sin_close_no_aparecen(self):
        """FileIDs que solo tienen CREATE no deben estar en el set."""
        paquetes = [
            pkt("CREATE", file_id="FID_X", timestamp=1.0),
            pkt("WRITE", file_id="FID_X", timestamp=1.1),
            # Sin CLOSE
        ]
        fids = _pre_escanear_fids_con_close(paquetes)
        assert "FID_X" not in fids

    def test_multiple_close_mismo_fid(self):
        """Si un FileID tiene multiples CLOSE, debe aparecer una vez."""
        paquetes = [
            pkt("CREATE", file_id="FID_A", timestamp=1.0),
            pkt("CLOSE", file_id="FID_A", timestamp=1.2),
            pkt("CREATE", file_id="FID_A", timestamp=2.0),
            pkt("CLOSE", file_id="FID_A", timestamp=2.2),
        ]
        fids = _pre_escanear_fids_con_close(paquetes)
        assert "FID_A" in fids
        assert len(fids) == 1


# =========================================================================
# TESTS: Agrupacion jerarquica v4 (SOLO casos NO cubiertos por pipeline validator)
# =========================================================================
# Cubierto por validar_pipeline_v4.py (NO duplicar):
#   - create_sin_close_descartado -> caso_5
#   - find_integrado_en_operacion_activa -> caso_4
#   - find_fuera_de_operacion_activa -> caso_6
#   - mismo_fid_raiz_reutilizado -> caso_7

class TestAgrupacionV4:

    def test_operacion_simple_un_fid(self):
        """Un solo FileID con CREATE+CLOSE debe formar 1 operacion simple."""
        paquetes = [
            pkt("CREATE", file_id="FID_A", timestamp=1.0),
            pkt("WRITE", file_id="FID_A", timestamp=1.1),
            pkt("CLOSE", file_id="FID_A", timestamp=1.2),
        ]
        ops = agrupar_por_operacion_v4(paquetes)
        assert len(ops) == 1
        assert ops[0].es_simple is True
        assert ops[0].fileid_raiz == "FID_A"
        assert ops[0].num_file_ids == 1
        assert ops[0].num_paquetes == 3

    def test_operacion_compuesta_dos_fids(self):
        """
        CREATE raiz + CREATE subordinado dentro del intervalo.
        Debe formar 1 operacion compuesta con 2 FileIDs.
        """
        paquetes = [
            pkt("CREATE", file_id="FID_A", timestamp=1.0),  # raiz
            pkt("CREATE", file_id="FID_B", timestamp=1.1),  # subordinado
            pkt("WRITE", file_id="FID_B", timestamp=1.2),
            pkt("CLOSE", file_id="FID_B", timestamp=1.3),
            pkt("CLOSE", file_id="FID_A", timestamp=1.4),  # cierra raiz
        ]
        ops = agrupar_por_operacion_v4(paquetes)
        assert len(ops) == 1
        assert ops[0].es_simple is False
        assert ops[0].fileid_raiz == "FID_A"
        assert ops[0].num_file_ids == 2
        assert ops[0].num_paquetes == 5

    def test_operacion_compuesta_tres_fids(self):
        """
        CREATE raiz + 2 subordinados.
        Debe formar 1 operacion compuesta con 3 FileIDs.
        """
        paquetes = [
            pkt("CREATE", file_id="FID_A", timestamp=1.0),  # raiz
            pkt("CREATE", file_id="FID_B", timestamp=1.1),  # sub 1
            pkt("WRITE", file_id="FID_B", timestamp=1.2),
            pkt("CLOSE", file_id="FID_B", timestamp=1.3),
            pkt("CREATE", file_id="FID_C", timestamp=1.4),  # sub 2
            pkt("READ", file_id="FID_C", timestamp=1.5),
            pkt("CLOSE", file_id="FID_C", timestamp=1.6),
            pkt("CLOSE", file_id="FID_A", timestamp=1.7),  # cierra raiz
        ]
        ops = agrupar_por_operacion_v4(paquetes)
        assert len(ops) == 1
        assert ops[0].es_simple is False
        assert ops[0].num_file_ids == 3
        assert ops[0].num_paquetes == 8

    def test_dos_operaciones_independientes(self):
        """
        Dos operaciones independientes (distintos raiz, sin solapamiento).
        Deben formarse 2 operaciones.
        """
        paquetes = [
            pkt("CREATE", file_id="FID_A", timestamp=1.0),
            pkt("WRITE", file_id="FID_A", timestamp=1.1),
            pkt("CLOSE", file_id="FID_A", timestamp=1.2),
            pkt("CREATE", file_id="FID_B", timestamp=2.0),
            pkt("READ", file_id="FID_B", timestamp=2.1),
            pkt("CLOSE", file_id="FID_B", timestamp=2.2),
        ]
        ops = agrupar_por_operacion_v4(paquetes)
        assert len(ops) == 2
        assert ops[0].fileid_raiz == "FID_A"
        assert ops[1].fileid_raiz == "FID_B"
        assert ops[0].es_simple is True
        assert ops[1].es_simple is True

    def test_paquetes_fuera_de_fids_abiertos_descartados(self):
        """
        Paquetes de un FileID que no esta en fids_abiertos deben descartarse.
        """
        paquetes = [
            pkt("CREATE", file_id="FID_A", timestamp=1.0),
            pkt("WRITE", file_id="FID_A", timestamp=1.1),
            pkt("CLOSE", file_id="FID_A", timestamp=1.2),
            # FID_B no esta abierto -> debe descartarse
            pkt("WRITE", file_id="FID_B", timestamp=1.3),
        ]
        ops = agrupar_por_operacion_v4(paquetes)
        assert len(ops) == 1
        assert ops[0].num_paquetes == 3  # solo FID_A

    def test_query_info_integrado(self):
        """
        QUERY_INFO sin FileID debe integrarse en la operacion activa.
        """
        paquetes = [
            pkt("CREATE", file_id="FID_A", timestamp=1.0),
            pkt("QUERY_INFO", file_id=None, timestamp=1.1),
            pkt("CLOSE", file_id="FID_A", timestamp=1.2),
        ]
        ops = agrupar_por_operacion_v4(paquetes)
        assert len(ops) == 1
        assert ops[0].num_paquetes == 3

    def test_orden_cronologico_mantenido(self):
        """Las operaciones deben estar ordenadas por timestamp de inicio."""
        paquetes = [
            pkt("CREATE", file_id="FID_C", timestamp=3.0),
            pkt("CLOSE", file_id="FID_C", timestamp=3.1),
            pkt("CREATE", file_id="FID_A", timestamp=1.0),
            pkt("CLOSE", file_id="FID_A", timestamp=1.1),
            pkt("CREATE", file_id="FID_B", timestamp=2.0),
            pkt("CLOSE", file_id="FID_B", timestamp=2.1),
        ]
        ops = agrupar_por_operacion_v4(paquetes)
        tiempos = [op.timestamp_inicio for op in ops]
        assert tiempos == sorted(tiempos)


# =========================================================================
# TESTS: Extraccion de operaciones atomicas (NO cubierto por validators)
# =========================================================================

class TestExtraccionAtomicas:

    def test_extraer_de_operacion_simple(self):
        """De una operacion simple (1 FileID) debe extraerse 1 atomica."""
        paquetes = [
            pkt("CREATE", file_id="FID_A", timestamp=1.0),
            pkt("WRITE", file_id="FID_A", timestamp=1.1),
            pkt("CLOSE", file_id="FID_A", timestamp=1.2),
        ]
        op_comp = OperacionCompuesta(id_compuesta="test1", fileid_raiz="FID_A")
        for p in paquetes:
            op_comp.anyadir(p)
        op_comp.es_simple = True

        atomicas = extraer_operaciones_atomicas(op_comp)
        assert len(atomicas) == 1
        assert "FID_A" in atomicas[0].file_ids
        assert atomicas[0].num_paquetes == 3

    def test_extraer_de_operacion_compuesta(self):
        """De una operacion compuesta (2 FileIDs) deben extraerse 2 atomicas."""
        paquetes = [
            pkt("CREATE", file_id="FID_A", timestamp=1.0),
            pkt("CREATE", file_id="FID_B", timestamp=1.1),
            pkt("WRITE", file_id="FID_B", timestamp=1.2),
            pkt("CLOSE", file_id="FID_B", timestamp=1.3),
            pkt("CLOSE", file_id="FID_A", timestamp=1.4),
        ]
        op_comp = OperacionCompuesta(id_compuesta="test2", fileid_raiz="FID_A")
        for p in paquetes:
            op_comp.anyadir(p)
        op_comp.es_simple = False

        atomicas = extraer_operaciones_atomicas(op_comp)
        assert len(atomicas) == 2
        fids = [list(a.file_ids)[0] for a in atomicas if a.file_ids]
        assert "FID_A" in fids
        assert "FID_B" in fids

    def test_extraer_con_finds_integrados(self):
        """
        Los FINDs (sin FileID) no deben generar atomicas propias.
        Solo los paquetes CON FileID generan atomicas.
        """
        paquetes = [
            pkt("CREATE", file_id="FID_A", timestamp=1.0),
            pkt("QUERY_DIRECTORY", file_id=None, timestamp=1.1),
            pkt("READ", file_id="FID_A", timestamp=1.2),
            pkt("CLOSE", file_id="FID_A", timestamp=1.3),
        ]
        op_comp = OperacionCompuesta(id_compuesta="test3", fileid_raiz="FID_A")
        for p in paquetes:
            op_comp.anyadir(p)
        op_comp.es_simple = True

        atomicas = extraer_operaciones_atomicas(op_comp)
        assert len(atomicas) == 1  # solo FID_A, los FINDs no cuentan
        assert "FID_A" in atomicas[0].file_ids


# =========================================================================
# TESTS: Clasificacion de operaciones compuestas (NO cubierto por validators)
# =========================================================================
# Los validators prueban COPIAR CARPETA en pipeline (caso_3).
# Aqui probamos el RESTO de tipos compuestos directamente.

class TestClasificacionCompuestas:

    def test_clasificar_bajar_carpeta(self):
        """
        BAJAR CARPETA: CREATE(carpeta) + FIND + READ (sin WRITE), >=2 FileIDs.
        """
        paquetes = [
            pkt("CREATE", file_id="FID_DIR", timestamp=1.0,
                file_path="ruta/carpeta", create_options=CREATE_OPTIONS_DIRECTORIO),
            pkt("QUERY_DIRECTORY", file_id=None, timestamp=1.1),
            pkt("CREATE", file_id="FID_FILE", timestamp=1.2,
                file_path="ruta/carpeta/doc.pdf"),
            pkt("READ", file_id="FID_FILE", read_len=4096, timestamp=1.3),
            pkt("CLOSE", file_id="FID_FILE", timestamp=1.4),
            pkt("CLOSE", file_id="FID_DIR", timestamp=1.5),
        ]
        op_comp = OperacionCompuesta(id_compuesta="test_bajar", fileid_raiz="FID_DIR")
        for p in paquetes:
            op_comp.anyadir(p)
        op_comp.es_simple = False

        tipo = clasificar_operacion_compuesta(op_comp)
        assert tipo == "BAJAR CARPETA"

    def test_clasificar_subir_carpeta(self):
        """
        SUBIR CARPETA: CREATE(carpeta) + FIND + WRITE (sin READ), >=2 FileIDs.
        """
        paquetes = [
            pkt("CREATE", file_id="FID_DIR", timestamp=1.0,
                file_path="ruta/carpeta", create_options=CREATE_OPTIONS_DIRECTORIO),
            pkt("QUERY_DIRECTORY", file_id=None, timestamp=1.1),
            pkt("CREATE", file_id="FID_FILE", timestamp=1.2,
                file_path="ruta/carpeta/doc.pdf"),
            pkt("WRITE", file_id="FID_FILE", write_len=8192, timestamp=1.3),
            pkt("CLOSE", file_id="FID_FILE", timestamp=1.4),
            pkt("CLOSE", file_id="FID_DIR", timestamp=1.5),
        ]
        op_comp = OperacionCompuesta(id_compuesta="test_subir", fileid_raiz="FID_DIR")
        for p in paquetes:
            op_comp.anyadir(p)
        op_comp.es_simple = False

        tipo = clasificar_operacion_compuesta(op_comp)
        assert tipo == "SUBIR CARPETA"

    def test_clasificar_comprimir_archivo(self):
        """
        COMPRIMIR ARCHIVO: CREATE(archivo) + READ + CREATE + SET_INFO(0x13) + WRITE.
        Exactamente 2 FileIDs.
        """
        paquetes = [
            pkt("CREATE", file_id="FID_ORIG", timestamp=1.0,
                file_path="ruta/doc.pdf"),
            pkt("READ", file_id="FID_ORIG", read_len=4096, timestamp=1.1),
            pkt("CREATE", file_id="FID_ZIP", timestamp=1.2,
                file_path="ruta/doc.zip"),
            pkt("SET_INFO", file_id="FID_ZIP",
                info_class=INFO_CLASS_ALLOCATION_INFO, timestamp=1.3),
            pkt("WRITE", file_id="FID_ZIP", write_len=4096, timestamp=1.4),
            pkt("CLOSE", file_id="FID_ZIP", timestamp=1.5),
            pkt("CLOSE", file_id="FID_ORIG", timestamp=1.6),
        ]
        op_comp = OperacionCompuesta(id_compuesta="test_zip", fileid_raiz="FID_ORIG")
        for p in paquetes:
            op_comp.anyadir(p)
        op_comp.es_simple = False

        tipo = clasificar_operacion_compuesta(op_comp)
        assert tipo == "COMPRIMIR ARCHIVO"

    def test_clasificar_operacion_compleja(self):
        """
        OPERACION COMPLEJA: multi-FileID sin patron especifico reconocido.
        """
        paquetes = [
            pkt("CREATE", file_id="FID_A", timestamp=1.0),
            pkt("CREATE", file_id="FID_B", timestamp=1.1),
            pkt("READ", file_id="FID_B", read_len=4096, timestamp=1.2),
            pkt("CLOSE", file_id="FID_B", timestamp=1.3),
            pkt("CLOSE", file_id="FID_A", timestamp=1.4),
        ]
        op_comp = OperacionCompuesta(id_compuesta="test_compleja", fileid_raiz="FID_A")
        for p in paquetes:
            op_comp.anyadir(p)
        op_comp.es_simple = False

        tipo = clasificar_operacion_compuesta(op_comp)
        # Sin patron especifico -> OPERACION COMPLEJA
        assert tipo == "OPERACION COMPLEJA"

    def test_operacion_simple_no_clasifica_compuesta(self):
        """Operacion simple (1 FileID) no debe pasar por clasificador de compuestas."""
        paquetes = [
            pkt("CREATE", file_id="FID_A", timestamp=1.0),
            pkt("WRITE", file_id="FID_A", write_len=8192, timestamp=1.1),
            pkt("CLOSE", file_id="FID_A", timestamp=1.2),
        ]
        op_comp = OperacionCompuesta(id_compuesta="test_simple", fileid_raiz="FID_A")
        for p in paquetes:
            op_comp.anyadir(p)
        op_comp.es_simple = True

        # Si es simple, no se llama a clasificar_operacion_compuesta
        # En el pipeline, se usa la clasificacion de la atomica
        atomicas = extraer_operaciones_atomicas(op_comp)
        assert len(atomicas) == 1
        tipo = clasificar_operacion(atomicas[0])
        assert tipo == "SUBIR ARCHIVO"


# =========================================================================
# TESTS: Reporte v4 (NO cubierto por validators)
# =========================================================================

class TestReporteV4:

    def test_generar_reporte_sin_ops(self, capsys):
        """Reporte con 0 operaciones no debe fallar."""
        generar_reporte_v4([], solo_resumen=True)
        captured = capsys.readouterr()
        assert "RESUMEN FINAL" in captured.out

    def test_generar_reporte_con_ops(self, capsys):
        """Reporte con operaciones debe mostrar resumen."""
        op1 = OperacionCompuesta(id_compuesta="test1", fileid_raiz="FID_A")
        op1.es_simple = True
        op1.tipo_atomica = "SUBIR ARCHIVO"
        op1.anyadir(pkt("CREATE", file_id="FID_A", timestamp=1.0))
        op1.anyadir(pkt("CLOSE", file_id="FID_A", timestamp=1.1))

        op2 = OperacionCompuesta(id_compuesta="test2", fileid_raiz="FID_B")
        op2.es_simple = False
        op2.tipo_compuesta = "COPIAR CARPETA"
        op2.anyadir(pkt("CREATE", file_id="FID_B", timestamp=2.0))
        op2.anyadir(pkt("CLOSE", file_id="FID_B", timestamp=2.1))

        generar_reporte_v4([op1, op2], solo_resumen=True)
        captured = capsys.readouterr()
        assert "SUBIR ARCHIVO" in captured.out
        assert "COPIAR CARPETA" in captured.out


# =========================================================================
# TESTS: CSV real (si esta disponible) - NO cubierto por validators
# =========================================================================

class TestCSVReal:

    @pytest.fixture
    def ruta_traza_user(self):
        """Ruta a la traza de usuario real."""
        ruta = os.path.join(os.path.dirname(__file__), "..", "Trazas", "Traza_user_5.csv")
        if not os.path.isfile(ruta):
            pytest.skip(f"Traza de usuario no encontrada: {ruta}")
        return ruta

    def test_leer_csv_real_no_vacia(self, ruta_traza_user):
        """La traza real debe contener paquetes."""
        paquetes = leer_csv(ruta_traza_user)
        assert len(paquetes) > 0
        assert len(paquetes) > 10000

    def test_agrupar_csv_real_produce_ops(self, ruta_traza_user):
        """La traza real debe producir operaciones con v4."""
        paquetes = leer_csv(ruta_traza_user)
        ops = agrupar_por_operacion_v4(paquetes)
        assert len(ops) > 0
        # Debe haber al menos algunas operaciones simples y compuestas
        simples = sum(1 for op in ops if op.es_simple)
        compuestas = sum(1 for op in ops if not op.es_simple)
        assert simples > 0, "Debe haber operaciones simples"
        # No exigimos compuestas porque depende de la traza
