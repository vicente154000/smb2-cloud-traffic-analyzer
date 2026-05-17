#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
convertir_tabla_a_csv.py — Convierte el formato tabla (TXT) de Wireshark
al formato CSV que usa analizador_smb2.py.

Uso:
    python src/convertir_tabla_a_csv.py Trazas/Traza_ransom_formato_tabla.txt
    python src/convertir_tabla_a_csv.py Trazas/Traza_ransom_formato_tabla.txt -o Trazas/Traza_ransom.csv
"""

import sys
import os
import csv

# Comandos de ruido del SO que ignoramos
RUIDO_OS = {"NEGOTIATE", "SESSION_SETUP", "LOGOFF", "TREE_CONNECT",
            "TREE_DISCONNECT", "ECHO", "CANCEL", "LOCK",
            "CHANGE_NOTIFY", "OPLOCK_BREAK", "FLUSH"}


def convertir(ruta_entrada, ruta_salida=None):
    """
    Lee el formato tabla (separado por espacios) y escribe un CSV
    compatible con analizador_smb2.py.

    Formato tabla:
      IP_src Port_src IP_dst Port_dst ConnID Timestamp Comando Error TreeID ...

    Por comando:
      CREATE:   ... CreateOptions 0 size allocationSize Ruta
      CLOSE:    ... fileID creationTime lastWrite lastChange fileAttributes
      READ:     ... 5 5 fileID length offset dataLength dataRemaining
      WRITE:    ... 5 5 fileID length offset dataLength
      SET_INFO: ... fileID infoType infoClass
      QUERY_INFO: ... fileID infoType infoClass
      QUERY_DIRECTORY: ... fileID
    """
    if ruta_salida is None:
        base = os.path.splitext(ruta_entrada)[0]
        ruta_salida = base + ".csv"

    filas_csv = []
    with open(ruta_entrada, "r", encoding="utf-8-sig") as f:
        for num_linea, linea in enumerate(f, 1):
            linea = linea.strip()
            if not linea:
                continue
            partes = linea.split()

            if len(partes) < 9:
                continue

            comando = partes[6].strip().upper()

            if comando in RUIDO_OS:
                continue

            # Columnas fijas del CSV de salida (como en Traza_user_5.csv)
            # Col: 0=IP_src, 1=Port_src, 2=IP_dst, 3=Port_dst, 4=ConnID,
            #      5=Timestamp, 6=, 7=, 8=, 9=Comando, 10=Error,
            #      11=, 12=, 13=TreeID, 14=FileID, 15=CreateOptions/InfoClass/Length,
            #      16=, 17=Offset, 18=, 19=FilePath

            ip_src = partes[0]
            port_src = partes[1]
            ip_dst = partes[2]
            port_dst = partes[3]
            conn_id = partes[4]
            timestamp = partes[5]
            error = partes[7]

            # En el formato tabla, el TreeID solo aparece en TREE_CONNECT.
            # Como TREE_CONNECT se filtra como ruido, el resto de comandos
            # no tienen TreeID en una columna fija. Para CREATE/CLOSE/etc.,
            # la posicion 8 es el primer campo especifico del comando (FileID).
            # Por tanto, tree_id = "0" para todos los comandos de usuario.
            tree_id = "0"
            resto = partes[8:]

            # Valores por defecto
            file_id = ""
            create_options = ""
            info_class = ""
            read_len = ""
            write_len = ""
            offset = ""
            file_path = ""

            if comando == "CREATE":
                # CREATE error fileID createOptions 0 size allocationSize Ruta
                if len(resto) >= 6:
                    file_id = resto[0] if resto[0] != "0" else ""
                    create_options = resto[1]
                    file_path = " ".join(resto[5:])
                elif len(resto) >= 1:
                    file_id = resto[0] if resto[0] != "0" else ""

            elif comando == "CLOSE":
                if len(resto) >= 1:
                    file_id = resto[0] if resto[0] != "0" else ""

            elif comando == "READ":
                # READ error 5 5 fileID length offset dataLength dataRemaining
                if len(resto) >= 5:
                    file_id = resto[2] if resto[2] != "0" else ""
                    read_len = resto[3]
                    offset = resto[4]

            elif comando == "WRITE":
                # WRITE error 5 5 fileID length offset dataLength
                if len(resto) >= 5:
                    file_id = resto[2] if resto[2] != "0" else ""
                    write_len = resto[3]
                    offset = resto[4]

            elif comando == "SET_INFO":
                # SET_INFO error fileID infoType infoClass
                if len(resto) >= 3:
                    file_id = resto[0] if resto[0] != "0" else ""
                    info_class = resto[2]

            elif comando == "QUERY_INFO":
                if len(resto) >= 1:
                    file_id = resto[0] if resto[0] != "0" else ""

            elif comando == "QUERY_DIRECTORY":
                if len(resto) >= 1:
                    file_id = resto[0] if resto[0] != "0" else ""

            # Construir fila CSV (mismo formato que Traza_user_5.csv)
            # Col: 0=IP_src, 1=Port_src, 2=IP_dst, 3=Port_dst, 4=ConnID,
            #      5=Timestamp, 6=, 7=, 8=, 9=Comando, 10=Error,
            #      11=, 12=, 13=TreeID, 14=FileID,
            #      15=CreateOptions/Length (READ/WRITE),
            #      16=InfoClass (SET_INFO),
            #      17=Offset, 18=, 19=FilePath
            if comando == "SET_INFO":
                col_15 = create_options  # normalmente vacio para SET_INFO
                col_16 = info_class
            elif comando in ("READ", "WRITE"):
                col_15 = read_len or write_len
                col_16 = ""  # InfoClass no aplica
            elif comando == "CREATE":
                col_15 = create_options
                col_16 = ""  # InfoClass no aplica
            else:
                col_15 = create_options or info_class or read_len or write_len
                col_16 = info_class if comando == "SET_INFO" else ""

            fila = [
                ip_src, port_src, ip_dst, port_dst, conn_id,
                timestamp, "", "", "",
                comando,
                error, "", "", tree_id,
                file_id,
                col_15,
                col_16,
                offset, "", file_path
            ]
            filas_csv.append(fila)

    # Escribir CSV
    with open(ruta_salida, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        # Escribir cabeceras (formato compatible con analizador_smb2.py)
        writer.writerow(["Client IP", "Client Port", "Server IP", "Server Port",
                        "TCP Connection Id", "Timestamp comienzo(REQ)",
                        "", "", "", "SMB2 command name", "HayError?",
                        "", "", "Tree id", "", "", "", "", "", ""])
        # 14 filas de cabecera (el analizador salta las primeras 15)
        for _ in range(13):
            writer.writerow([""] * 20)
        writer.writerow([""] * 20)  # fila 15 (vacia, el analizador empieza en 17)
        writer.writerow([""] * 20)  # fila 16
        # Datos
        for fila in filas_csv:
            writer.writerow(fila)

    print(f"Convertido: {ruta_entrada} -> {ruta_salida}")
    print(f"  {len(filas_csv)} paquetes SMB2 escritos")
    return ruta_salida


def main():
    if len(sys.argv) < 2:
        print("Uso: python src/convertir_tabla_a_csv.py <archivo.txt> [-o salida.csv]")
        print("Ejemplo: python src/convertir_tabla_a_csv.py Trazas/Traza_ransom_formato_tabla.txt")
        sys.exit(1)

    ruta_entrada = sys.argv[1]

    if "-o" in sys.argv:
        idx = sys.argv.index("-o")
        ruta_salida = sys.argv[idx + 1]
    else:
        ruta_salida = None

    if not os.path.isfile(ruta_entrada):
        print(f"Error: No se encuentra el archivo: {ruta_entrada}")
        sys.exit(1)

    convertir(ruta_entrada, ruta_salida)


if __name__ == "__main__":
    main()
