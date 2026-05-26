# Plan de validación para v4

## Problema
Los tests actuales validan el diseño, no la realidad. En v2 los tests pasaban pero el análisis real era incorrecto porque el agrupamiento no reflejaba el tráfico SMB2 real.

## Estrategia: 3 líneas de defensa independientes

```
Linea 1: Tests unitarios (ya existen)
  - test_clasificacion.py (30 tests)
  - test_integracion_v4.py (37 tests)
  - test_integracion.py (14 tests, v2 legacy)
  - test_convertidor.py (7 tests)
  Util: detectan regresiones al modificar el código
  Debil: validan el diseño, no la realidad

Linea 2: Validador de pipeline completo (NUEVO)
  - Construye casos con operaciones ENTRELAZADAS
  - Ejecuta pipeline v4 completo
  - Verifica clasificacion de cada operacion
  Fuerte: detecta errores de agrupamiento

Linea 3: Cross-validation con capturas reales (NUEVO)
  - Usa capturas Wireshark reales de operaciones conocidas
  - Convierte a CSV, ejecuta v4, verifica resultado
  Fuerte: rompe la circularidad (validacion externa)
```

---

## Linea 2: Validador de pipeline completo

### Archivo: `tests/validar_pipeline_v4.py`

Construye casos de prueba donde MULTIPLES operaciones comparten el mismo flujo de paquetes (como en tráfico real). Cada caso es un CSV completo que se procesa con el pipeline v4.

### Casos de prueba

#### Caso 1: Operaciones secuenciales (sin solapamiento)
```
CREATE FID_A (raiz)
WRITE FID_A
CLOSE FID_A
CREATE FID_B (raiz)
READ FID_B
CLOSE FID_B
```
Esperado: 2 operaciones simples (SUBIR ARCHIVO, BAJAR ARCHIVO)

#### Caso 2: Operaciones entremezcladas (solapamiento parcial)
```
CREATE FID_A (raiz op1)
CREATE FID_B (raiz op2)     <- segundo CREATE mientras op1 activa
WRITE FID_A
READ FID_B
CLOSE FID_A                  <- cierra op1
CLOSE FID_B                  <- cierra op2
```
Esperado: 2 operaciones simples (SUBIR ARCHIVO, BAJAR ARCHIVO)
**Problema potencial**: v4 detecta CREATE FID_B como subordinado de FID_A porque op1 esta activa.
**Solucion**: v4 trata CREATE como nuevo raiz si el FileID no esta en fids_abiertos y tiene CLOSE.

#### Caso 3: Operacion compuesta real (COPIAR CARPETA)
```
CREATE FID_DIR (raiz, carpeta)
QUERY_DIRECTORY (FIND)
CREATE FID_FILE1 (subordinado)
READ FID_FILE1
CREATE FID_FILE2 (subordinado)
WRITE FID_FILE2
CLOSE FID_FILE2
CLOSE FID_FILE1
CLOSE FID_DIR
```
Esperado: 1 operacion compuesta (COPIAR CARPETA) con 3 atomicas

#### Caso 4: FINDs integrados en operacion activa
```
CREATE FID_A (raiz)
QUERY_DIRECTORY (FIND, sin FileID)
READ FID_A
CLOSE FID_A
```
Esperado: 1 operacion simple con FIND integrado

#### Caso 5: CREATE sin CLOSE descartado
```
CREATE FID_HUERFANO (sin CLOSE)
CREATE FID_A (raiz)
WRITE FID_A
CLOSE FID_A
```
Esperado: 1 operacion simple (SUBIR ARCHIVO), FID_HUERFANO descartado

#### Caso 6: Multiples operaciones con FINDs fuera
```
CREATE FID_A (raiz)
WRITE FID_A
CLOSE FID_A
QUERY_DIRECTORY (FIND, sin operacion activa)
QUERY_DIRECTORY (FIND, sin operacion activa)
```
Esperado: 1 operacion simple (SUBIR ARCHIVO) + 1 grupo de FINDs

#### Caso 7: Reutilizacion de FileID raiz
```
CREATE FID_A (raiz op1)
WRITE FID_A
CLOSE FID_A
CREATE FID_A (raiz op2)
READ FID_A
CLOSE FID_A
```
Esperado: 2 operaciones simples (SUBIR ARCHIVO, BAJAR ARCHIVO)

### Formato del validador

```python
def main():
    casos = [
        ("Operaciones secuenciales", caso_1_paquetes, [
            ("SUBIR ARCHIVO", 1),   # (tipo_esperado, num_fileids)
            ("BAJAR ARCHIVO", 1),
        ]),
        ("Operaciones entremezcladas", caso_2_paquetes, [
            ("SUBIR ARCHIVO", 1),
            ("BAJAR ARCHIVO", 1),
        ]),
        ...
    ]
    
    for nombre, paquetes, expectativas in casos:
        ops = agrupar_por_operacion_v4(paquetes)
        # Pipeline completo...
        verificar(ops, expectativas)
```

---

## Linea 3: Cross-validation con Wireshark

### Archivo: `tests/validar_con_wireshark.py`

### Capturas disponibles

| Captura | Operacion esperada | Estado |
|---------|-------------------|--------|
| `CarpetaConFicheros.pcapng` | LISTAR DIRECTORIO / operacion con carpeta | Pendiente |
| `createCarpeta.pcapng` | CREAR CARPETA | Pendiente |
| `downloadCarpetaCompleta.pcapng` | BAJAR CARPETA | Pendiente |
| `downloadFile_archivoPequenio.pcapng` | BAJAR ARCHIVO | Pendiente |
| `downloadFILEentero_12-04.pcapng` | BAJAR ARCHIVO | Pendiente |
| `pruebaMirar.pcapng` | ? (exploratoria) | Pendiente |
| `renameOperation.pcapng` | RENOMBRAR/MOVER | Pendiente |
| `variasOperaciones.pcapng` | Multiples operaciones | Pendiente |

### Proceso

1. Cada `.pcapng` se convierte a formato tabla TXT usando TShark
2. El TXT se convierte a CSV usando `convertir_tabla_a_csv.py`
3. El CSV se procesa con el pipeline v4
4. El resultado se muestra para **verificacion manual** (tu validas con Wireshark)

### Formato del script

```python
def main():
    capturas = [
        ("Wireshark/createCarpeta.pcapng", "CREAR CARPETA"),
        ("Wireshark/downloadFile_archivoPequenio.pcapng", "BAJAR ARCHIVO"),
        ...
    ]
    
    for ruta_pcapng, operacion_esperada in capturas:
        # 1. Convertir pcapng -> txt (tshark)
        # 2. Convertir txt -> csv
        # 3. Ejecutar v4
        # 4. Mostrar resultado
        print(f"\n{'='*60}")
        print(f"  Captura: {ruta_pcapng}")
        print(f"  Esperado: {operacion_esperada}")
        print(f"{'='*60}")
        # Mostrar resultado para verificacion manual
```

**Nota**: Este script requiere TShark instalado. Si no esta disponible, se salta automaticamente.

---

## Archivos a crear/modificar

### Nuevos archivos

1. **`tests/validar_pipeline_v4.py`** - Validador de pipeline completo (Linea 2)
   - ~300 lineas
   - 7 casos de prueba con operaciones entremezcladas
   - Ejecuta pipeline v4 completo
   - Verifica clasificacion de cada operacion

2. **`tests/validar_con_wireshark.py`** - Cross-validation con Wireshark (Linea 3)
   - ~200 lineas
   - Convierte capturas .pcapng a CSV
   - Ejecuta v4 y muestra resultados
   - Requiere TShark (salta si no disponible)

### Modificaciones

3. **`tests/validar_todas_operaciones.py`** - Actualizar para que tambien valide con v4
   - Anadir opcion `--v4` para usar pipeline v4
   - Mantener compatibilidad con v2

---

## Orden de implementacion

1. `tests/validar_pipeline_v4.py` (Linea 2) - Mas importante, detecta errores de agrupamiento
2. `tests/validar_con_wireshark.py` (Linea 3) - Cross-validation con capturas reales
3. Actualizar `tests/validar_todas_operaciones.py` para v4

---

## Como se gana confianza

1. **Linea 2**: Si el validador de pipeline pasa todos los casos con operaciones entremezcladas, sabemos que el agrupamiento funciona correctamente para escenarios realistas.

2. **Linea 3**: Si ejecutamos v4 sobre capturas Wireshark reales y tu verificas manualmente que el resultado coincide con lo que ves en Wireshark, tenemos validacion externa independiente del codigo.

3. **Tests**: Los tests existentes garantizan que no introducimos regresiones al modificar el codigo.
