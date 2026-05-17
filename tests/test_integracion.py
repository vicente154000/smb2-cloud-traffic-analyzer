# -*- coding: utf-8 -*-
"""
Tests de integracion para el pipeline completo del analizador SMB2.

Verifica que el flujo completo (leer CSV -> agrupar -> clasificar -> reporte)
funciona correctamente con datos de prueba y con trazas reales.

Ejecucion:
    pytest tests/test_integracion.py -v
    pytest tests/test_integracion.py -v --tb=short
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from collections import defaultdict
from analizador_smb2_v2 import (
    leer_csv, agrupar_por_operacion, clasificar_operacion,
    generar_reporte,
)


# =========================================================================
# TESTS: Pipeline completo con CSV de prueba
# =========================================================================

class TestPipelineCSV:

    def test_subir_archivo_desde_csv(self, csv_subir_archivo):
        """
        Pipeline completo con CSV de subida:
        - Leer CSV
        - Agrupar por operacion
        - Clasificar
        - Verificar que es SUBIR ARCHIVO
        """
        paquetes = leer_csv(csv_subir_archivo)
        assert len(paquetes) == 3, "Debe leer 3 paquetes (CREATE, WRITE, CLOSE)"

        operaciones = agrupar_por_operacion(paquetes)
        assert len(operaciones) == 1, "Debe formar 1 operacion"

        op = operaciones[0]
        op.tipo = clasificar_operacion(op)
        assert op.tipo == "SUBIR ARCHIVO"
        assert op.archivo == "ruta/doc.pdf"
        assert op.num_paquetes == 3
        assert op.num_writes == 1
        assert op.total_write == 8192

    def test_borrar_archivo_desde_csv(self, csv_borrar_archivo):
        """
        Pipeline completo con CSV de borrado.
        """
        paquetes = leer_csv(csv_borrar_archivo)
        assert len(paquetes) == 3

        operaciones = agrupar_por_operacion(paquetes)
        assert len(operaciones) == 1

        op = operaciones[0]
        op.tipo = clasificar_operacion(op)
        assert op.tipo == "BORRAR ARCHIVO"
        assert op.num_setinfo == 1

    def test_crear_carpeta_desde_csv(self, csv_crear_carpeta):
        """
        Pipeline completo con CSV de creacion de carpeta.
        """
        paquetes = leer_csv(csv_crear_carpeta)
        assert len(paquetes) == 2

        operaciones = agrupar_por_operacion(paquetes)
        assert len(operaciones) == 1

        op = operaciones[0]
        op.tipo = clasificar_operacion(op)
        assert op.tipo == "CREAR CARPETA"

    def test_operaciones_multiples(self, csv_operaciones_multiples):
        """
        CSV con 3 operaciones independientes (distintos FileID).
        Deben detectarse las 3 correctamente.
        """
        paquetes = leer_csv(csv_operaciones_multiples)
        assert len(paquetes) == 9  # 3 ops * 3 paqs

        operaciones = agrupar_por_operacion(paquetes)
        assert len(operaciones) == 3, "Debe formar 3 operaciones"

        # Clasificar
        for op in operaciones:
            op.tipo = clasificar_operacion(op)

        # Verificar tipos
        tipos = [op.tipo for op in operaciones]
        assert "SUBIR ARCHIVO" in tipos
        assert "BAJAR ARCHIVO" in tipos
        assert "BORRAR ARCHIVO" in tipos

        # Verificar orden cronologico
        tiempos = [op.timestamp_inicio for op in operaciones]
        assert tiempos == sorted(tiempos), "Operaciones deben estar ordenadas por tiempo"

    def test_filtrado_ruido(self, csv_con_ruido):
        """
        CSV con ruido (NEGOTIATE, SESSION_SETUP, etc.) debe filtrarse.
        Solo debe quedar la operacion real.
        """
        paquetes = leer_csv(csv_con_ruido)
        assert len(paquetes) == 3, "Solo deben quedar 3 paquetes (CREATE, WRITE, CLOSE)"

        operaciones = agrupar_por_operacion(paquetes)
        assert len(operaciones) == 1

        op = operaciones[0]
        op.tipo = clasificar_operacion(op)
        assert op.tipo == "SUBIR ARCHIVO"

    def test_create_sin_close(self, csv_create_sin_close):
        """
        CSV con CREATE sin CLOSE.
        El agrupamiento debe marcar la operacion como DESCONOCIDA (CREATE sin CLOSE).
        """
        paquetes = leer_csv(csv_create_sin_close)
        assert len(paquetes) == 1

        operaciones = agrupar_por_operacion(paquetes)
        assert len(operaciones) == 1

        op = operaciones[0]
        # El agrupamiento ya marca el tipo como "DESCONOCIDA (CREATE sin CLOSE)"
        assert "CREATE sin CLOSE" in op.tipo

    def test_async_noise_descartado(self, csv_async_noise):
        """
        CSV con paquetes basura entre CLOSE y siguiente CREATE.
        Esos paquetes deben descartarse.
        """
        paquetes = leer_csv(csv_async_noise)
        # 8 paquetes total: 3 (op1) + 2 (basura) + 3 (op2)
        assert len(paquetes) == 8

        operaciones = agrupar_por_operacion(paquetes)
        # Deben formarse 2 operaciones (los 2 paquetes basura se descartan)
        assert len(operaciones) == 2, (
            f"Esperaba 2 operaciones, obtuve {len(operaciones)}"
        )

        # Clasificar
        for op in operaciones:
            op.tipo = clasificar_operacion(op)

        assert all(op.tipo == "SUBIR ARCHIVO" for op in operaciones)


# =========================================================================
# TESTS: Reporte
# =========================================================================

class TestReporte:

    def test_generar_reporte_sin_ops(self, capsys):
        """Reporte con 0 operaciones no debe fallar."""
        generar_reporte([], solo_resumen=True)
        captured = capsys.readouterr()
        assert "RESUMEN FINAL" in captured.out

    def test_generar_reporte_con_ops(self, op_subir_archivo, op_bajar_archivo, capsys):
        """Reporte con operaciones debe mostrar resumen."""
        op_subir_archivo.tipo = "SUBIR ARCHIVO"
        op_bajar_archivo.tipo = "BAJAR ARCHIVO"
        generar_reporte([op_subir_archivo, op_bajar_archivo], solo_resumen=True)
        captured = capsys.readouterr()
        assert "SUBIR ARCHIVO" in captured.out
        assert "BAJAR ARCHIVO" in captured.out
        assert "1 vez" in captured.out  # cada tipo aparece 1 vez


# =========================================================================
# TESTS: Trazas reales (si estan disponibles)
# =========================================================================

class TestTrazasReales:

    @pytest.fixture
    def ruta_traza_user(self):
        """Ruta a la traza de usuario real."""
        ruta = os.path.join(os.path.dirname(__file__), "..", "Trazas", "Traza_user_5.csv")
        if not os.path.isfile(ruta):
            pytest.skip(f"Traza de usuario no encontrada: {ruta}")
        return ruta

    @pytest.fixture
    def ruta_traza_ransomware(self):
        """Ruta a la traza de ransomware real."""
        ruta = os.path.join(os.path.dirname(__file__), "..", "Trazas",
                            "Traza_ransom_formato_tabla.csv")
        if not os.path.isfile(ruta):
            pytest.skip(f"Traza de ransomware no encontrada: {ruta}")
        return ruta

    def test_traza_user_no_vacia(self, ruta_traza_user):
        """La traza de usuario debe contener paquetes."""
        paquetes = leer_csv(ruta_traza_user)
        assert len(paquetes) > 0, "La traza de usuario no debe estar vacia"
        assert len(paquetes) > 10000, "Debe tener mas de 10000 paquetes"

    def test_traza_user_operaciones(self, ruta_traza_user):
        """La traza de usuario debe producir operaciones."""
        paquetes = leer_csv(ruta_traza_user)
        operaciones = agrupar_por_operacion(paquetes)
        assert len(operaciones) > 0, "Debe producir al menos 1 operacion"
        assert len(operaciones) > 1000, "Debe producir mas de 1000 operaciones"

        # Clasificar
        for op in operaciones:
            op.tipo = clasificar_operacion(op)

        # Verificar distribucion esperada
        conteo = defaultdict(int)
        for op in operaciones:
            conteo[op.tipo] += 1

        # Debe haber SUBIR ARCHIVO como operacion mas frecuente
        assert conteo.get("SUBIR ARCHIVO", 0) > 0, "Debe haber subidas de archivo"
        assert conteo.get("BORRAR ARCHIVO", 0) > 0, "Debe haber borrados"
        assert conteo.get("BAJAR ARCHIVO", 0) > 0, "Debe haber descargas"
        assert conteo.get("RENOMBRAR/MOVER ARCHIVO", 0) > 0, "Debe haber renombrados"

        # DESCONOCIDA debe ser un porcentaje pequeno
        total = len(operaciones)
        desconocidas = conteo.get("DESCONOCIDA", 0)
        pct_desconocidas = (desconocidas / total) * 100
        assert pct_desconocidas < 5, (
            f"DESCONOCIDA no debe superar el 5% (actual: {pct_desconocidas:.1f}%)"
        )

    def test_traza_ransomware_no_vacia(self, ruta_traza_ransomware):
        """La traza de ransomware debe contener paquetes."""
        paquetes = leer_csv(ruta_traza_ransomware)
        assert len(paquetes) > 0
        assert len(paquetes) > 10000

    def test_traza_ransomware_operaciones(self, ruta_traza_ransomware):
        """La traza de ransomware debe producir operaciones."""
        paquetes = leer_csv(ruta_traza_ransomware)
        operaciones = agrupar_por_operacion(paquetes)
        assert len(operaciones) > 0
        assert len(operaciones) > 1000

        # Clasificar
        for op in operaciones:
            op.tipo = clasificar_operacion(op)

        conteo = defaultdict(int)
        for op in operaciones:
            conteo[op.tipo] += 1

        # Ransomware debe tener CREAR ARCHIVO VACIO como operacion frecuente
        assert conteo.get("CREAR ARCHIVO VACIO", 0) > 0, (
            "Ransomware debe crear archivos vacios"
        )
        assert conteo.get("BORRAR ARCHIVO", 0) > 0, "Ransomware debe borrar archivos"

    def test_comparativa_user_vs_ransomware(self, ruta_traza_user, ruta_traza_ransomware):
        """
        Comparacion directa: el ransomware debe tener un perfil
        diferente al del usuario normal.
        """
        # --- Usuario ---
        paq_user = leer_csv(ruta_traza_user)
        ops_user = agrupar_por_operacion(paq_user)
        for op in ops_user:
            op.tipo = clasificar_operacion(op)

        conteo_user = defaultdict(int)
        for op in ops_user:
            conteo_user[op.tipo] += 1

        # --- Ransomware ---
        paq_ransom = leer_csv(ruta_traza_ransomware)
        ops_ransom = agrupar_por_operacion(paq_ransom)
        for op in ops_ransom:
            op.tipo = clasificar_operacion(op)

        conteo_ransom = defaultdict(int)
        for op in ops_ransom:
            conteo_ransom[op.tipo] += 1

        # El usuario debe tener SUBIR ARCHIVO, el ransomware no (o muy poco)
        assert conteo_user.get("SUBIR ARCHIVO", 0) > conteo_ransom.get("SUBIR ARCHIVO", 0), (
            "Usuario debe subir mas archivos que el ransomware"
        )

        # El ransomware debe tener CREAR ARCHIVO VACIO, el usuario no (o muy poco)
        assert conteo_ransom.get("CREAR ARCHIVO VACIO", 0) > conteo_user.get("CREAR ARCHIVO VACIO", 0), (
            "Ransomware debe crear mas archivos vacios que el usuario"
        )
