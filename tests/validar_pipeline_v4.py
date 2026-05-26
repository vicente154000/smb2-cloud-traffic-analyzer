#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Validador de pipeline completo v4 (Linea 2 de defensa).

Construye casos de prueba con operaciones ENTRELAZADAS (como en trafico real)
y ejecuta el pipeline v4 completo: agrupar -> extraer atomicas -> clasificar.

Uso:
    python tests/validar_pipeline_v4.py
    python tests/validar_pipeline_v4.py -v   # verbose

Esto NO genera CSV intermedio. Construye los paquetes directamente y ejecuta
el pipeline v4 sobre ellos, verificando que cada operacion se clasifica
correctamente incluso cuando los paquetes estan entremezclados.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))  # para importar helpers

from analizador_smb2_v4 import (
    PaqueteSMB2, Operacion, OperacionCompuesta,
    _pre_escanear_fids_con_close,
    agrupar_por_operacion_v4,
    extraer_operaciones_atomicas,
    clasificar_operacion,
    clasificar_operacion_compuesta,
)
from helpers import pkt


# =========================================================================
# CASOS DE PRUEBA
# =========================================================================

def caso_1_secuenciales():
    """Caso 1: Operaciones secuenciales (sin solapamiento).
    
    CREATE FID_A (raiz)
    WRITE FID_A
    CLOSE FID_A
    CREATE FID_B (raiz)
    READ FID_B
    CLOSE FID_B
    
    Esperado: 2 operaciones simples (SUBIR ARCHIVO, BAJAR ARCHIVO)
    """
    return [
        pkt("CREATE", linea=1, timestamp=1.0, file_id="FID_A",
            file_path="ruta/subir.pdf", create_options=0x60),
        pkt("WRITE", linea=2, timestamp=1.1, file_id="FID_A",
            write_len=4096, write_offset=0),
        pkt("CLOSE", linea=3, timestamp=1.2, file_id="FID_A"),
        pkt("CREATE", linea=4, timestamp=2.0, file_id="FID_B",
            file_path="ruta/bajar.pdf", create_options=0x60),
        pkt("READ", linea=5, timestamp=2.1, file_id="FID_B",
            read_len=8192, read_offset=0),
        pkt("CLOSE", linea=6, timestamp=2.2, file_id="FID_B"),
    ]


def caso_2_entremezcladas():
    """Caso 2: Operaciones entremezcladas (solapamiento parcial).
    
    CREATE FID_A (raiz op1)
    CREATE FID_B (raiz op2)     <- segundo CREATE mientras op1 activa
    WRITE FID_A
    READ FID_B
    CLOSE FID_A                  <- cierra op1
    CLOSE FID_B                  <- cierra op2
    
    Esperado: 2 operaciones simples (SUBIR ARCHIVO, BAJAR ARCHIVO)
    Problema potencial: v4 podria tratar FID_B como subordinado de FID_A.
    Solucion: v4 trata CREATE como nuevo raiz si el FileID no esta en
    fids_abiertos y tiene CLOSE.
    """
    return [
        pkt("CREATE", linea=1, timestamp=1.0, file_id="FID_A",
            file_path="ruta/subir.pdf", create_options=0x60),
        pkt("CREATE", linea=2, timestamp=1.1, file_id="FID_B",
            file_path="ruta/bajar.pdf", create_options=0x60),
        pkt("WRITE", linea=3, timestamp=1.2, file_id="FID_A",
            write_len=4096, write_offset=0),
        pkt("READ", linea=4, timestamp=1.3, file_id="FID_B",
            read_len=8192, read_offset=0),
        pkt("CLOSE", linea=5, timestamp=1.4, file_id="FID_A"),
        pkt("CLOSE", linea=6, timestamp=1.5, file_id="FID_B"),
    ]


def caso_3_copiar_carpeta():
    """Caso 3: Operacion compuesta real (COPIAR CARPETA).
    
    CREATE FID_DIR (raiz, carpeta)
    QUERY_DIRECTORY (FIND)
    CREATE FID_FILE1 (subordinado)
    READ FID_FILE1
    CREATE FID_FILE2 (subordinado)
    WRITE FID_FILE2
    CLOSE FID_FILE2
    CLOSE FID_FILE1
    CLOSE FID_DIR
    
    Esperado: 1 operacion compuesta (COPIAR CARPETA) con 3 atomicas
    """
    return [
        pkt("CREATE", linea=1, timestamp=1.0, file_id="FID_DIR",
            file_path="ruta/copiar_carpeta", create_options=0x01),
        pkt("QUERY_DIRECTORY", linea=2, timestamp=1.1, file_id="FID_DIR"),
        pkt("CREATE", linea=3, timestamp=1.2, file_id="FID_FILE1",
            file_path="ruta/copiar_carpeta/a.txt", create_options=0x60),
        pkt("READ", linea=4, timestamp=1.3, file_id="FID_FILE1",
            read_len=4096, read_offset=0),
        pkt("CREATE", linea=5, timestamp=1.4, file_id="FID_FILE2",
            file_path="ruta/copiar_carpeta/b.txt", create_options=0x60),
        pkt("WRITE", linea=6, timestamp=1.5, file_id="FID_FILE2",
            write_len=4096, write_offset=0),
        pkt("CLOSE", linea=7, timestamp=1.6, file_id="FID_FILE2"),
        pkt("CLOSE", linea=8, timestamp=1.7, file_id="FID_FILE1"),
        pkt("CLOSE", linea=9, timestamp=1.8, file_id="FID_DIR"),
    ]


def caso_4_finds_integrados():
    """Caso 4: FINDs integrados en operacion activa.
    
    CREATE FID_A (raiz)
    QUERY_DIRECTORY (FIND, sin FileID)
    READ FID_A
    CLOSE FID_A
    
    Esperado: 1 operacion simple con FIND integrado
    """
    return [
        pkt("CREATE", linea=1, timestamp=1.0, file_id="FID_A",
            file_path="ruta/archivo.pdf", create_options=0x60),
        pkt("QUERY_DIRECTORY", linea=2, timestamp=1.1, file_id=""),
        pkt("READ", linea=3, timestamp=1.2, file_id="FID_A",
            read_len=4096, read_offset=0),
        pkt("CLOSE", linea=4, timestamp=1.3, file_id="FID_A"),
    ]


def caso_5_create_sin_close():
    """Caso 5: CREATE sin CLOSE descartado.
    
    CREATE FID_HUERFANO (sin CLOSE)
    CREATE FID_A (raiz)
    WRITE FID_A
    CLOSE FID_A
    
    Esperado: 1 operacion simple (SUBIR ARCHIVO), FID_HUERFANO descartado
    """
    return [
        pkt("CREATE", linea=1, timestamp=1.0, file_id="FID_HUERFANO",
            file_path="ruta/huerfano.pdf", create_options=0x60),
        pkt("CREATE", linea=2, timestamp=2.0, file_id="FID_A",
            file_path="ruta/subir.pdf", create_options=0x60),
        pkt("WRITE", linea=3, timestamp=2.1, file_id="FID_A",
            write_len=4096, write_offset=0),
        pkt("CLOSE", linea=4, timestamp=2.2, file_id="FID_A"),
    ]


def caso_6_finds_fuera():
    """Caso 6: Multiples operaciones con FINDs fuera.
    
    CREATE FID_A (raiz)
    WRITE FID_A
    CLOSE FID_A
    QUERY_DIRECTORY (FIND, sin operacion activa)
    QUERY_DIRECTORY (FIND, sin operacion activa)
    
    Esperado: 1 operacion simple (SUBIR ARCHIVO) + FINDs sueltos
    """
    return [
        pkt("CREATE", linea=1, timestamp=1.0, file_id="FID_A",
            file_path="ruta/subir.pdf", create_options=0x60),
        pkt("WRITE", linea=2, timestamp=1.1, file_id="FID_A",
            write_len=4096, write_offset=0),
        pkt("CLOSE", linea=3, timestamp=1.2, file_id="FID_A"),
        pkt("QUERY_DIRECTORY", linea=4, timestamp=2.0, file_id=""),
        pkt("QUERY_DIRECTORY", linea=5, timestamp=2.1, file_id=""),
    ]


def caso_7_reutilizacion_fid():
    """Caso 7: Reutilizacion de FileID raiz.
    
    CREATE FID_A (raiz op1)
    WRITE FID_A
    CLOSE FID_A
    CREATE FID_A (raiz op2)
    READ FID_A
    CLOSE FID_A
    
    Esperado: 2 operaciones simples (SUBIR ARCHIVO, BAJAR ARCHIVO)
    """
    return [
        pkt("CREATE", linea=1, timestamp=1.0, file_id="FID_A",
            file_path="ruta/subir.pdf", create_options=0x60),
        pkt("WRITE", linea=2, timestamp=1.1, file_id="FID_A",
            write_len=4096, write_offset=0),
        pkt("CLOSE", linea=3, timestamp=1.2, file_id="FID_A"),
        pkt("CREATE", linea=4, timestamp=2.0, file_id="FID_A",
            file_path="ruta/bajar.pdf", create_options=0x60),
        pkt("READ", linea=5, timestamp=2.1, file_id="FID_A",
            read_len=8192, read_offset=0),
        pkt("CLOSE", linea=6, timestamp=2.2, file_id="FID_A"),
    ]


# =========================================================================
# VERIFICACION
# =========================================================================

def ejecutar_pipeline(paquetes):
    """Ejecuta el pipeline v4 completo sobre una lista de paquetes.
    
    Returns:
        list[OperacionCompuesta]: operaciones compuestas resultantes
    """
    # 1. Pre-escanear FileIDs con CLOSE
    fids_con_close = _pre_escanear_fids_con_close(paquetes)
    
    # 2. Agrupar por operacion v4
    ops_compuestas = agrupar_por_operacion_v4(paquetes)
    
    # 3. Para cada operacion compuesta: extraer atomicas y clasificar
    for op_comp in ops_compuestas:
        # Extraer operaciones atomicas
        atomicas = extraer_operaciones_atomicas(op_comp)
        op_comp.operaciones_atomicas = atomicas
        
        # Clasificar cada operacion atomica
        for op_atom in atomicas:
            op_atom.tipo = clasificar_operacion(op_atom)
        
        # Si es compuesta, clasificar como compuesta
        if not op_comp.es_simple:
            op_comp.tipo_compuesta = clasificar_operacion_compuesta(op_comp)
        else:
            # Si es simple, el tipo es el de su unica atomica
            if atomicas:
                op_comp.tipo_atomica = atomicas[0].tipo
    
    return ops_compuestas


def verificar_resultados(ops_compuestas, expectativas, verbose=False):
    """Verifica que las operaciones coinciden con las expectativas.
    
    Args:
        ops_compuestas: resultado de ejecutar_pipeline()
        expectativas: lista de (tipo_esperado, num_fileids, es_simple)
    
    Returns:
        tuple: (aciertos, fallos, detalles)
    """
    aciertos = 0
    fallos = 0
    detalles = []
    
    for i, (op_comp, (tipo_esp, num_fids_esp, simple_esp)) in enumerate(
            zip(ops_compuestas, expectativas)):
        
        # Determinar tipo real
        tipo_real = op_comp.tipo_compuesta or op_comp.tipo_atomica or "SIN CLASIFICAR"
        num_fids_real = op_comp.num_file_ids
        simple_real = op_comp.es_simple
        
        # Verificar
        ok_tipo = tipo_real == tipo_esp
        ok_fids = num_fids_real == num_fids_esp
        ok_simple = simple_real == simple_esp
        ok = ok_tipo and ok_fids and ok_simple
        
        if ok:
            estado = "OK"
            aciertos += 1
        else:
            estado = "FALLO"
            fallos += 1
        
        detalles.append({
            "indice": i + 1,
            "tipo_esperado": tipo_esp,
            "tipo_real": tipo_real,
            "num_fids_esperado": num_fids_esp,
            "num_fids_real": num_fids_real,
            "simple_esperado": simple_esp,
            "simple_real": simple_real,
            "ok_tipo": ok_tipo,
            "ok_fids": ok_fids,
            "ok_simple": ok_simple,
            "estado": estado,
            "op_comp": op_comp,
        })
        
        if verbose and not ok:
            print(f"    [DEBUG] Op {i+1}: esperado={tipo_esp}, real={tipo_real}, "
                  f"fids={num_fids_real}, simple={simple_real}")
            for p in op_comp.paquetes:
                print(f"      {p}")
    
    return aciertos, fallos, detalles


# =========================================================================
# MAIN
# =========================================================================

def main():
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    
    print("=" * 70)
    print("  VALIDADOR DE PIPELINE V4 (Linea 2)")
    print("  Prueba el pipeline completo con operaciones entremezcladas")
    print("=" * 70)
    print()
    
    # Definir casos de prueba
    casos = [
        ("Caso 1: Secuenciales (sin solapamiento)",
         caso_1_secuenciales(),
         [("SUBIR ARCHIVO", 1, True),
          ("BAJAR ARCHIVO", 1, True)]),
        
        ("Caso 2: Entremezcladas (solapamiento parcial)",
         caso_2_entremezcladas(),
         [("OPERACION COMPLEJA", 2, False)]),
        
        ("Caso 3: Compuesta real (COPIAR CARPETA)",
         caso_3_copiar_carpeta(),
         [("COPIAR CARPETA", 3, False)]),
        
        ("Caso 4: FINDs integrados en operacion activa",
         caso_4_finds_integrados(),
         [("BAJAR ARCHIVO", 1, True)]),
        
        ("Caso 5: CREATE sin CLOSE descartado",
         caso_5_create_sin_close(),
         [("SUBIR ARCHIVO", 1, True)]),
        
        ("Caso 6: FINDs fuera de operacion activa",
         caso_6_finds_fuera(),
         [("SUBIR ARCHIVO", 1, True)]),
        
        ("Caso 7: Reutilizacion de FileID raiz",
         caso_7_reutilizacion_fid(),
         [("SUBIR ARCHIVO", 1, True),
          ("BAJAR ARCHIVO", 1, True)]),
    ]
    
    total_aciertos = 0
    total_fallos = 0
    
    for nombre_caso, paquetes, expectativas in casos:
        print(f"\n  {'=' * 66}")
        print(f"  {nombre_caso}")
        print(f"  {'=' * 66}")
        
        if verbose:
            print(f"\n  Paquetes de entrada ({len(paquetes)}):")
            for p in paquetes:
                print(f"    {p}")
        
        # Ejecutar pipeline
        ops_compuestas = ejecutar_pipeline(paquetes)
        
        if verbose:
            print(f"\n  Operaciones resultantes ({len(ops_compuestas)}):")
            for op_comp in ops_compuestas:
                print(f"    {op_comp.resumen()}")
                for op_atom in op_comp.operaciones_atomicas:
                    print(f"      -> {op_atom.resumen()}")
        
        # Verificar
        aciertos, fallos, detalles = verificar_resultados(
            ops_compuestas, expectativas, verbose)
        
        total_aciertos += aciertos
        total_fallos += fallos
        
        # Mostrar resultados del caso
        print(f"\n  {'#':>3} | {'ESPERADO':30s} | {'REAL':30s} | {'FIDS':5s} | ESTADO")
        print(f"  {'-' * 3} | {'-' * 30} | {'-' * 30} | {'-' * 5} | {'-' * 5}")
        for det in detalles:
            fids_str = f"{det['num_fids_real']}/{det['num_fids_esperado']}"
            print(f"  {det['indice']:3d} | {det['tipo_esperado']:30s} | "
                  f"{det['tipo_real']:30s} | {fids_str:5s} | {det['estado']}")
        
        if fallos > 0:
            print(f"\n  [!] {fallos} fallo(s) en este caso")
            if not verbose:
                print("  Ejecuta con -v para ver detalles de depuracion")
    
    # Resumen global
    total = total_aciertos + total_fallos
    print()
    print("=" * 70)
    print(f"  RESUMEN GLOBAL")
    print("=" * 70)
    print(f"    Total casos:     {len(casos)}")
    print(f"    Total ops:       {total}")
    print(f"    Aciertos:        {total_aciertos:3d} / {total}")
    print(f"    Fallos:          {total_fallos:3d} / {total}")
    print()
    
    if total_fallos == 0:
        print("  [OK] PIPELINE V4 VALIDADO CORRECTAMENTE")
        print("  Todas las operaciones entremezcladas se clasifican bien")
    else:
        print("  [FALLO] HAY OPERACIONES CON CLASIFICACION INCORRECTA")
        print("  Revisa los casos fallidos arriba")
    print()
    
    return total_fallos == 0


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
