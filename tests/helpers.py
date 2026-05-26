# -*- coding: utf-8 -*-
"""
Helpers compartidos para tests y validadores del analizador SMB2 v4.

Proporciona la funcion pkt() para crear PaqueteSMB2 de forma rapida,
evitando la duplicacion de codigo en test_integracion_v4.py,
validar_pipeline_v4.py y validar_todas_operaciones.py.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from analizador_smb2_v4 import PaqueteSMB2


def pkt(comando, linea=1, timestamp=1.0, tree_id=1, file_id="FID001",
        file_path=None, create_options=None, info_class=None,
        read_len=None, write_len=None, read_offset=None,
        write_offset=None, tiene_error=False):
    """Crea un PaqueteSMB2 con valores por defecto."""
    return PaqueteSMB2(
        linea=linea, comando=comando, timestamp=timestamp,
        tree_id=tree_id, file_id=file_id, file_path=file_path,
        create_options=create_options, info_class=info_class,
        read_len=read_len, write_len=write_len,
        read_offset=read_offset, write_offset=write_offset,
        tiene_error=tiene_error,
    )
