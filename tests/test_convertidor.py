# -*- coding: utf-8 -*-
"""
Tests de regresion para el convertidor de formato tabla a CSV.

Verifica que convertir_tabla_a_csv.py produce el formato CSV correcto
compatible con el analizador SMB2.

Ejecucion:
    pytest tests/test_convertidor.py -v
    pytest tests/test_convertidor.py -v --tb=short
"""

import sys
import os
import csv
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from convertir_tabla_a_csv import convertir


# =========================================================================
# FIXTURES: Archivos TXT de prueba en formato tabla
# =========================================================================

@pytest.fixture
def txt_create():
    """Linea de CREATE en formato tabla."""
    return (
        "192.168.1.1 49152 192.168.1.100 445 conn1 1.000 CREATE 0 "
        "FID001 0x60 0 1024 0 ruta/documento.pdf\n"
    )


@pytest.fixture
def txt_close():
    """Linea de CLOSE en formato tabla."""
    return (
        "192.168.1.1 49152 192.168.1.100 445 conn1 1.100 CLOSE 0 "
        "FID001 0 0 0 0\n"
    )


@pytest.fixture
def txt_read():
    """Linea de READ en formato tabla."""
    return (
        "192.168.1.1 49152 192.168.1.100 445 conn1 1.050 READ 0 "
        "5 5 FID001 4096 0 4096 0\n"
    )


@pytest.fixture
def txt_write():
    """Linea de WRITE en formato tabla."""
    return (
        "192.168.1.1 49152 192.168.1.100 445 conn1 1.050 WRITE 0 "
        "5 5 FID001 8192 0 8192\n"
    )


@pytest.fixture
def txt_setinfo_borrar():
    """Linea de SET_INFO con InfoClass=0x0D (borrar) en formato tabla."""
    return (
        "192.168.1.1 49152 192.168.1.100 445 conn1 1.050 SET_INFO 0 "
        "FID001 2 13\n"
    )


@pytest.fixture
def txt_setinfo_renombrar():
    """Linea de SET_INFO con InfoClass=0x0A (renombrar) en formato tabla."""
    return (
        "192.168.1.1 49152 192.168.1.100 445 conn1 1.050 SET_INFO 0 "
        "FID001 2 10\n"
    )


@pytest.fixture
def txt_ruido():
    """Lineas de ruido (deben filtrarse)."""
    return (
        "192.168.1.1 49152 192.168.1.100 445 conn1 0.000 NEGOTIATE 0\n"
        "192.168.1.1 49152 192.168.1.100 445 conn1 0.001 SESSION_SETUP 0\n"
        "192.168.1.1 49152 192.168.1.100 445 conn1 0.002 TREE_CONNECT 0 1\n"
    )


def _escribir_txt_temp(lineas):
    """Crea un archivo TXT temporal con las lineas dadas."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                    encoding="utf-8", delete=False)
    f.write(lineas)
    f.close()
    return f.name


# =========================================================================
# TESTS: Conversion de comandos individuales
# =========================================================================

class TestConversionIndividual:

    def test_convertir_create(self, txt_create):
        """CREATE debe convertirse correctamente."""
        ruta_txt = _escribir_txt_temp(txt_create)
        ruta_csv = ruta_txt.replace(".txt", ".csv")
        try:
            resultado = convertir(ruta_txt)
            assert resultado == ruta_csv

            with open(ruta_csv, "r", encoding="utf-8-sig") as f:
                lector = csv.reader(f)
                filas = list(lector)

            # Saltar cabeceras (16 filas)
            filas_datos = [f for f in filas[16:] if any(celda.strip() for celda in f)]
            assert len(filas_datos) == 1, "Debe haber 1 fila de datos"

            fila = filas_datos[0]
            assert fila[9] == "CREATE", "Columna 9 debe ser CREATE"
            assert fila[14] == "FID001", "Columna 14 debe ser FileID"
            assert fila[15] == "0x60", "Columna 15 debe ser CreateOptions"
            assert fila[19] == "ruta/documento.pdf", "Columna 19 debe ser FilePath"
        finally:
            os.unlink(ruta_txt)
            if os.path.exists(ruta_csv):
                os.unlink(ruta_csv)

    def test_convertir_close(self, txt_close):
        """CLOSE debe convertirse correctamente."""
        ruta_txt = _escribir_txt_temp(txt_close)
        ruta_csv = ruta_txt.replace(".txt", ".csv")
        try:
            resultado = convertir(ruta_txt)
            filas_datos = self._leer_datos(resultado)
            assert len(filas_datos) == 1
            assert filas_datos[0][9] == "CLOSE"
            assert filas_datos[0][14] == "FID001"
        finally:
            os.unlink(ruta_txt)
            if os.path.exists(ruta_csv):
                os.unlink(ruta_csv)

    def test_convertir_read(self, txt_read):
        """READ debe convertirse correctamente."""
        ruta_txt = _escribir_txt_temp(txt_read)
        ruta_csv = ruta_txt.replace(".txt", ".csv")
        try:
            resultado = convertir(ruta_txt)
            filas_datos = self._leer_datos(resultado)
            assert len(filas_datos) == 1
            fila = filas_datos[0]
            assert fila[9] == "READ"
            assert fila[14] == "FID001", "FileID debe estar en col 14"
            assert fila[15] == "4096", "Length debe estar en col 15"
            assert fila[17] == "0", "Offset debe estar en col 17"
        finally:
            os.unlink(ruta_txt)
            if os.path.exists(ruta_csv):
                os.unlink(ruta_csv)

    def test_convertir_write(self, txt_write):
        """WRITE debe convertirse correctamente."""
        ruta_txt = _escribir_txt_temp(txt_write)
        ruta_csv = ruta_txt.replace(".txt", ".csv")
        try:
            resultado = convertir(ruta_txt)
            filas_datos = self._leer_datos(resultado)
            assert len(filas_datos) == 1
            fila = filas_datos[0]
            assert fila[9] == "WRITE"
            assert fila[14] == "FID001"
            assert fila[15] == "8192", "Length debe estar en col 15"
            assert fila[17] == "0", "Offset debe estar en col 17"
        finally:
            os.unlink(ruta_txt)
            if os.path.exists(ruta_csv):
                os.unlink(ruta_csv)

    def test_convertir_setinfo_borrar(self, txt_setinfo_borrar):
        """SET_INFO con InfoClass=0x0D debe poner InfoClass en col 16."""
        ruta_txt = _escribir_txt_temp(txt_setinfo_borrar)
        ruta_csv = ruta_txt.replace(".txt", ".csv")
        try:
            resultado = convertir(ruta_txt)
            filas_datos = self._leer_datos(resultado)
            assert len(filas_datos) == 1
            fila = filas_datos[0]
            assert fila[9] == "SET_INFO"
            assert fila[14] == "FID001"
            # InfoClass debe ir a columna 16, no 15
            assert fila[15] == "", "CreateOptions debe estar vacio para SET_INFO"
            assert fila[16] == "13", "InfoClass=13 (0x0D) debe estar en col 16"
        finally:
            os.unlink(ruta_txt)
            if os.path.exists(ruta_csv):
                os.unlink(ruta_csv)

    def test_convertir_setinfo_renombrar(self, txt_setinfo_renombrar):
        """SET_INFO con InfoClass=0x0A debe poner InfoClass en col 16."""
        ruta_txt = _escribir_txt_temp(txt_setinfo_renombrar)
        ruta_csv = ruta_txt.replace(".txt", ".csv")
        try:
            resultado = convertir(ruta_txt)
            filas_datos = self._leer_datos(resultado)
            assert len(filas_datos) == 1
            fila = filas_datos[0]
            assert fila[9] == "SET_INFO"
            assert fila[16] == "10", "InfoClass=10 (0x0A) debe estar en col 16"
        finally:
            os.unlink(ruta_txt)
            if os.path.exists(ruta_csv):
                os.unlink(ruta_csv)

    @staticmethod
    def _leer_datos(ruta_csv):
        """Lee un CSV y devuelve solo las filas de datos (sin cabeceras)."""
        with open(ruta_csv, "r", encoding="utf-8-sig") as f:
            lector = csv.reader(f)
            filas = list(lector)
        return [f for f in filas[16:] if any(celda.strip() for celda in f)]


# =========================================================================
# TESTS: Filtrado de ruido
# =========================================================================

class TestFiltradoRuido:

    def test_filtrar_negociate(self, txt_ruido, txt_create):
        """NEGOTIATE, SESSION_SETUP, TREE_CONNECT deben filtrarse."""
        contenido = txt_ruido + txt_create
        ruta_txt = _escribir_txt_temp(contenido)
        ruta_csv = ruta_txt.replace(".txt", ".csv")
        try:
            resultado = convertir(ruta_txt)
            filas_datos = TestConversionIndividual._leer_datos(resultado)
            # Solo debe quedar el CREATE
            assert len(filas_datos) == 1, "Solo debe quedar 1 fila (CREATE)"
            assert filas_datos[0][9] == "CREATE"
        finally:
            os.unlink(ruta_txt)
            if os.path.exists(ruta_csv):
                os.unlink(ruta_csv)


# =========================================================================
# TESTS: Formato CSV de salida
# =========================================================================

class TestFormatoCSV:

    def test_cabeceras_correctas(self, txt_create):
        """El CSV debe tener 16 filas de cabecera antes de los datos."""
        ruta_txt = _escribir_txt_temp(txt_create)
        ruta_csv = ruta_txt.replace(".txt", ".csv")
        try:
            resultado = convertir(ruta_txt)
            with open(resultado, "r", encoding="utf-8-sig") as f:
                lector = csv.reader(f)
                filas = list(lector)

            # Fila 0 debe tener las cabeceras de columnas
            assert "SMB2 command name" in filas[0][9], (
                "Fila 0 debe tener cabecera SMB2 command name en col 9"
            )
            assert "Tree id" in filas[0][13], (
                "Fila 0 debe tener cabecera Tree id en col 13"
            )

            # Filas 1-15 deben estar vacias (o casi)
            for i in range(1, 16):
                assert len(filas[i]) >= 10, f"Fila {i} debe tener al menos 10 columnas"

            # Fila 16+ deben ser datos
            assert len(filas) > 16, "Debe haber filas de datos"
        finally:
            os.unlink(ruta_txt)
            if os.path.exists(ruta_csv):
                os.unlink(ruta_csv)

    def test_columnas_correctas(self, txt_create):
        """El CSV debe tener 20 columnas por fila."""
        ruta_txt = _escribir_txt_temp(txt_create)
        ruta_csv = ruta_txt.replace(".txt", ".csv")
        try:
            resultado = convertir(ruta_txt)
            with open(resultado, "r", encoding="utf-8-sig") as f:
                lector = csv.reader(f)
                for i, fila in enumerate(lector):
                    assert len(fila) == 20, (
                        f"Fila {i}: esperaba 20 columnas, obtuve {len(fila)}"
                    )
        finally:
            os.unlink(ruta_txt)
            if os.path.exists(ruta_csv):
                os.unlink(ruta_csv)


# =========================================================================
# TESTS: Pipeline completo (convertir + analizar)
# =========================================================================

class TestPipelineCompleto:

    def test_convertir_y_analizar_subida(self):
        """
        Conversion de TXT a CSV + analisis completo.
        Verifica que el CSV generado por el convertidor es compatible
        con el analizador.
        """
        from analizador_smb2_v2 import leer_csv, agrupar_por_operacion, clasificar_operacion

        # Crear TXT con una operacion de subida
        lineas = (
            "192.168.1.1 49152 192.168.1.100 445 conn1 1.000 CREATE 0 "
            "FID001 0x60 0 1024 ruta/doc.pdf\n"
            "192.168.1.1 49152 192.168.1.100 445 conn1 1.050 WRITE 0 "
            "5 5 FID001 8192 0 8192\n"
            "192.168.1.1 49152 192.168.1.100 445 conn1 1.100 CLOSE 0 "
            "FID001 0 0 0 0\n"
        )
        ruta_txt = _escribir_txt_temp(lineas)
        ruta_csv = ruta_txt.replace(".txt", ".csv")
        try:
            # Convertir
            convertir(ruta_txt)

            # Analizar
            paquetes = leer_csv(ruta_csv)
            assert len(paquetes) == 3, "Debe leer 3 paquetes"

            operaciones = agrupar_por_operacion(paquetes)
            assert len(operaciones) == 1, "Debe formar 1 operacion"

            op = operaciones[0]
            op.tipo = clasificar_operacion(op)
            assert op.tipo == "SUBIR ARCHIVO", (
                f"Esperaba SUBIR ARCHIVO, obtuve {op.tipo}"
            )
        finally:
            os.unlink(ruta_txt)
            if os.path.exists(ruta_csv):
                os.unlink(ruta_csv)

    def test_convertir_y_analizar_borrado(self):
        """
        Conversion + analisis de operacion de borrado.
        """
        from analizador_smb2_v2 import leer_csv, agrupar_por_operacion, clasificar_operacion

        lineas = (
            "192.168.1.1 49152 192.168.1.100 445 conn1 2.000 CREATE 0 "
            "FID002 0x60 0 2048 ruta/borrar.pdf\n"
            "192.168.1.1 49152 192.168.1.100 445 conn1 2.050 SET_INFO 0 "
            "FID002 2 13\n"
            "192.168.1.1 49152 192.168.1.100 445 conn1 2.100 CLOSE 0 "
            "FID002 0 0 0 0\n"
        )
        ruta_txt = _escribir_txt_temp(lineas)
        ruta_csv = ruta_txt.replace(".txt", ".csv")
        try:
            convertir(ruta_txt)
            paquetes = leer_csv(ruta_csv)
            operaciones = agrupar_por_operacion(paquetes)
            op = operaciones[0]
            op.tipo = clasificar_operacion(op)
            assert op.tipo == "BORRAR ARCHIVO"
        finally:
            os.unlink(ruta_txt)
            if os.path.exists(ruta_csv):
                os.unlink(ruta_csv)
