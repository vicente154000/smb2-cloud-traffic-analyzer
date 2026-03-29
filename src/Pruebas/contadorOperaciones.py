import pandas as pd
import time

# Ahora apuntamos al CSV que generaste
file_path_csv = './Trazas/Traza_user_5.csv'

try:
    start_time = time.time()
    
    # 1. Lectura del CSV (Mucho más rápido que el ODS)
    df = pd.read_csv(file_path_csv)
    
    # 2. Limpieza: Saltamos las filas de encabezados inútiles (hasta la 14)
    df_clean = df.iloc[14:].copy()
    
    end_time = time.time()
    print(f"Archivo CSV cargado y limpiado en {end_time - start_time:.4f} segundos.")

    # 3. Buscamos las operaciones CREATE
    # Usamos la columna 'SMB2 command name' que ya existe en el CSV
    creaciones = df_clean[df_clean['SMB2 command name'].str.strip() == 'CREATE'].copy()
    print(f"Número total de operaciones CREATE: {len(creaciones)}")

    # 4. Inferencia de CARPETAS
    # Buscamos el valor 1 o 33 en 'Unnamed: 15' (que es CreateOptions)
    # Convertimos a float primero por si acaso y luego a int/str
    carpetas = creaciones[creaciones['Unnamed: 15'].astype(str).str.contains('1|33', na=False)]
    
    print(f"De los {len(creaciones)} CREATE, {len(carpetas)} han sido identificados como CARPETAS.")

    # 5. Mostrar resultados
    print("\nPrimeras 10 rutas de carpetas detectadas:")
    # La columna 19 es el FilePath
    print(carpetas['Unnamed: 19'].head(10))

except FileNotFoundError:
    print("Error: El archivo CSV no existe. Ejecuta primero la conversión de ODS a CSV.")
except Exception as e:
    print(f"Error al procesar los datos: {e}")