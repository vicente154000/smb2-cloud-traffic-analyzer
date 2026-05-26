# Plan v4: Analizador SMB2 con operaciones simples y compuestas

## Resumen del acuerdo

Nuevo pipeline de 4 pasos:
1. **Agrupar CREATE-CLOSE** con algoritmo v4 (jerarquía raíz/subordinados)
2. **Extraer operaciones atómicas** hijas de cada compuesta
3. **Clasificar operaciones atómicas** (reutilizando `clasificar_operacion()` actual)
4. **Clasificar operaciones compuestas** (nuevo clasificador sobre paquetes raw)

---

## 1. Estructura de datos

### `OperacionCompuesta` (nueva clase)

```python
@dataclass
class OperacionCompuesta:
    """Una operación que puede ser simple (1 FileID) o compuesta (múltiples FileIDs)."""
    # Identificación
    id: str                    # UUID o hash único
    fileid_raiz: str           # FileID del CREATE principal
    
    # Paquetes
    paquetes: List[PaqueteSMB2]  # Todos los paquetes en orden cronológico
    timestamp_inicio: float
    timestamp_fin: float
    
    # Operaciones atómicas hijas (extraídas de los paquetes)
    operaciones_atomicas: List[Operacion]
    
    # Flags
    es_simple: bool            # True = 1 solo FileID, False = múltiples FileIDs
    
    # Clasificaciones
    tipo_atomica: str | None   # Clasificación si es simple (ej: "SUBIR ARCHIVO")
    tipo_compuesta: str | None # Clasificación si es compuesta (ej: "COMPRIMIR ARCHIVO")
```

### `Operacion` (modificar la existente)

Añadir campo opcional:
```python
class Operacion:
    # ... campos existentes ...
    id_compuesta: str | None = None  # Si es atómica, a qué compuesta pertenece
```

---

## 2. Algoritmo de agregación v4

### `agrupar_por_operacion_v4(paquetes) -> List[OperacionCompuesta]`

```
Entrada: List[PaqueteSMB2] (ordenados cronológicamente del CSV)
Salida:  List[OperacionCompuesta]

Algoritmo:
1. Inicializar:
   - op_actual = None (OperacionCompuesta actual)
   - fids_abiertos = {}  # {fileid: timestamp_del_create}
   - fid_raiz = None

2. Para cada paquete en paquetes (orden cronológico):
   
   a. Si comando == CREATE:
      - Si op_actual is None:
          # Nuevo CREATE raíz → iniciar operación compuesta
          fid_raiz = paquete.file_id
          op_actual = OperacionCompuesta(id=uuid, fileid_raiz=fid_raiz)
          fids_abiertos = {fid_raiz: timestamp}
      - Sino:
          # CREATE dentro de operación activa → es subordinado
          fids_abiertos[paquete.file_id] = timestamp
      - Anyadir paquete a op_actual.paquetes
   
   b. Si comando == CLOSE:
      - Si op_actual is not None y paquete.file_id in fids_abiertos:
          - Anyadir paquete a op_actual.paquetes
          - Eliminar paquete.file_id de fids_abiertos
          - Si paquete.file_id == fid_raiz:
              # Se cerró el raíz → cerrar operación compuesta
              op_actual.timestamp_fin = paquete.timestamp
              op_actual.es_simple = (len(fids_abiertos_original) == 1)
              Añadir op_actual a resultado
              op_actual = None
              fids_abiertos = {}
   
   c. Si otro comando (READ, WRITE, SET_INFO, QUERY_DIRECTORY, etc.):
      - Si op_actual is not None y paquete.file_id in fids_abiertos:
          - Anyadir paquete a op_actual.paquetes
      - Sino:
          - Descartar paquete (pertenece a operación anterior o es huérfano)

3. Si queda op_actual sin cerrar → marcar como DESCONOCIDA y añadir a resultado
```

### Ejemplo visual

```
Paquetes cronológicos:
[CREATE FID_A]  ← raíz, inicia op_compuesta_1
  [READ FID_A]
  [QUERY_DIRECTORY FID_X]  ← FID_X no está en fids_abiertos → se descarta
  [CREATE FID_B]  ← subordinado, se añade a fids_abiertos
  [SET_INFO FID_B]
  [WRITE FID_B]
  [CLOSE FID_B]  ← se cierra FID_B, pero op_compuesta_1 sigue abierta
  [READ FID_B]   ← FID_B ya cerrado, pero estaba en fids_abiertos_original → se mete
  [CREATE FID_C]  ← otro subordinado
  [WRITE FID_C]
  [CLOSE FID_C]
[CLOSE FID_A]    ← se cierra el raíz → op_compuesta_1 termina

Resultado: 1 OperacionCompuesta con 3 FileIDs (FID_A, FID_B, FID_C)
```

---

## 3. Extracción de operaciones atómicas

### `extraer_operaciones_atomicas(op_compuesta) -> List[Operacion]`

Para cada FileID dentro de la compuesta, extraer su secuencia CREATE→CLOSE:

```python
def extraer_operaciones_atomicas(op_compuesta):
    """
    Toma los paquetes de una operación compuesta y extrae las operaciones
    atómicas (1 FileID cada una) que la componen.
    """
    atomicas = []
    paquetes = op_compuesta.paquetes
    
    # Separar paquetes por FileID
    grupos = defaultdict(list)
    for pkt in paquetes:
        if pkt.file_id:
            grupos[pkt.file_id].append(pkt)
    
    # Para cada FileID, crear una Operacion con su secuencia CREATE→CLOSE
    for fid, pkts in grupos.items():
        op = Operacion()
        op.id_compuesta = op_compuesta.id
        for pkt in pkts:
            op.anyadir(pkt)
        atomicas.append(op)
    
    return atomicas
```

---

## 4. Clasificador de operaciones atómicas

Reutilizar [`clasificar_operacion()`](src/analizador_smb2_v2.py:457) **sin cambios**. Se aplica a cada `Operacion` atómica extraída.

```python
for op_atomica in op_compuesta.operaciones_atomicas:
    op_atomica.tipo = clasificar_operacion(op_atomica)
```

---

## 5. Clasificador de operaciones compuestas (nuevo)

### `clasificar_operacion_compuesta(op_compuesta) -> str`

Opera directamente sobre `op_compuesta.paquetes` (lista completa de paquetes). Aplica solo reglas multi-FileID.

```python
def clasificar_operacion_compuesta(op_compuesta):
    """
    Clasifica una operación compuesta analizando la secuencia completa
    de paquetes. Solo aplica reglas que requieren múltiples FileIDs.
    """
    paquetes = op_compuesta.paquetes
    comandos = [p.comando for p in paquetes]
    fileids = set(p.file_id for p in paquetes if p.file_id)
    creates = [p for p in paquetes if p.comando == "CREATE"]
    
    # Si solo tiene 1 FileID, no es compuesta
    if len(fileids) < 2:
        return None  # No aplica, usar clasificación atómica
    
    # ---- Reglas multi-FileID (de la memoria TFG) ----
    
    # Regla 12: COPIAR CARPETA
    # CREATE(dir) + FIND* + CREATE* + READ* + WRITE* + CLOSE* (múltiples archivos)
    if _es_copiar_carpeta(paquetes, comandos, fileids, creates):
        return "COPIAR CARPETA"
    
    # Regla 13: COMPRIMIR ARCHIVO
    # CREATE(archivo) + READ + CREATE + SET_INFO(0x13) + WRITE + CLOSE + CLOSE
    if _es_comprimir_archivo(paquetes, comandos, fileids, creates):
        return "COMPRIMIR ARCHIVO"
    
    # Regla 14: COMPRIMIR CARPETA
    # CREATE(dir) + FIND + (CREATE+READ+CLOSE)*N + CREATE+SET_INFO(0x13)+WRITE+CLOSE
    if _es_comprimir_carpeta(paquetes, comandos, fileids, creates):
        return "COMPRIMIR CARPETA"
    
    # Regla 15: MODIFICAR ARCHIVO (editor)
    # CREATE + READ + IOCTL + WRITE + CLOSE con >=2 FileIDs
    if _es_modificar_archivo_editor(paquetes, comandos, fileids, creates):
        return "MODIFICAR ARCHIVO (editor)"
    
    # Regla 16: MODIFICAR ARCHIVO (comando atómico)
    if _es_modificar_archivo_atomico(paquetes, comandos, fileids, creates):
        return "MODIFICAR ARCHIVO (comando atómico)"
    
    # Regla 17: SUBIR CARPETA
    # CREATE(dir) + CREATE(archivo)* + WRITE* + CLOSE*
    if _es_subir_carpeta(paquetes, comandos, fileids, creates):
        return "SUBIR CARPETA"
    
    # Regla 18: BAJAR CARPETA
    # CREATE(dir) + CREATE(archivo)* + READ* + CLOSE*
    if _es_bajar_carpeta(paquetes, comandos, fileids, creates):
        return "BAJAR CARPETA"
    
    # Regla 19: OPERACION COMPLEJA (modif+borrar)
    if _es_operacion_compleja(paquetes, comandos, fileids, creates):
        return "OPERACION COMPLEJA (modif+borrar)"
    
    # Si tiene múltiples FileIDs pero no coincide con ningún patrón
    return "OPERACION COMPLEJA"
```

### Funciones auxiliares de detección

Cada `_es_*()` analiza la secuencia de paquetes para detectar el patrón. Ejemplo:

```python
def _es_comprimir_archivo(paquetes, comandos, fileids, creates):
    """
    Patrón de la memoria TFG:
    CREATE(original) + READ + CREATE(comprimido) + SET_INFO(0x13) + WRITE + CLOSE + CLOSE
    
    Condiciones:
    - Exactamente 2 FileIDs
    - El primer CREATE es de archivo (no directorio)
    - Hay READ del primer FileID
    - El segundo CREATE tiene SET_INFO(AllocationInfo=0x13) + WRITE
    """
    if len(fileids) != 2 or len(creates) != 2:
        return False
    if _es_directorio(creates[0].create_options):
        return False
    
    # Verificar secuencia: READ del FID1 antes del 2º CREATE
    # Verificar SET_INFO(0x13) + WRITE del FID2
    # ... lógica de verificación
    
    return True
```

---

## 6. Pipeline completo (main)

```python
def main():
    # 1. Leer CSV
    paquetes = leer_csv(ruta_csv)
    
    # 2. Agrupar por operación (v4)
    operaciones_compuestas = agrupar_por_operacion_v4(paquetes)
    
    # 3. Para cada operación compuesta:
    for op_comp in operaciones_compuestas:
        # 3a. Extraer operaciones atómicas hijas
        op_comp.operaciones_atomicas = extraer_operaciones_atomicas(op_comp)
        
        # 3b. Clasificar cada atómica
        for op_atom in op_comp.operaciones_atomicas:
            op_atom.tipo = clasificar_operacion(op_atom)
        
        # 3c. Clasificar la compuesta (si tiene múltiples FileIDs)
        if not op_comp.es_simple:
            op_comp.tipo_compuesta = clasificar_operacion_compuesta(op_comp)
        else:
            # Si es simple, usar la clasificación de su única atómica
            op_comp.tipo_atomica = op_comp.operaciones_atomicas[0].tipo
    
    # 4. Generar reporte
    generar_reporte_v4(operaciones_compuestas)
```

---

## 7. Archivos a crear/modificar

### Nuevo archivo: `src/analizador_smb2_v4.py`

Contendrá todo el pipeline v4. Basado en `analizador_smb2_v2.py` pero con:

| Componente | Origen |
|-----------|--------|
| `PaqueteSMB2` | Copiar de v2 (sin cambios) |
| `Operacion` | Copiar de v2 + añadir `id_compuesta` |
| `OperacionCompuesta` | **Nueva** |
| `leer_csv()` | Copiar de v2 (sin cambios) |
| `agrupar_por_operacion_v4()` | **Nuevo algoritmo** |
| `extraer_operaciones_atomicas()` | **Nueva** |
| `clasificar_operacion()` | Copiar de v2 (sin cambios) |
| `clasificar_operacion_compuesta()` | **Nuevo** |
| `_es_comprimir_archivo()` | **Nueva** (y similares para cada regla) |
| `generar_reporte_v4()` | **Nuevo** (reporte con simple/compuesta) |
| `main()` | **Nuevo** (pipeline v4) |

### Modificar: `tests/validar_todas_operaciones.py`

Añadir casos de prueba para el pipeline v4 completo (agrupar + clasificar).

### Modificar: `tests/test_integracion.py`

Añadir tests de integración para v4 con trazas reales.

---

## 8. Estrategia de pruebas

### Tests unitarios (nuevos en `test_clasificacion.py` o nuevo archivo)

| Test | Descripción |
|------|-------------|
| `test_agrupar_v4_simple` | 1 FileID → 1 operación simple |
| `test_agrupar_v4_compuesta` | 2 FileIDs anidados → 1 operación compuesta |
| `test_agrupar_v4_asincronia_descartada` | FileID sin CREATE dentro → se descarta |
| `test_agrupar_v4_paquetes_fuera_rango` | Paquetes de subordinado fuera de rango → se meten |
| `test_clasificar_compuesta_comprimir_archivo` | Paquetes de COMPRIMIR ARCHIVO → clasifica bien |
| `test_clasificar_compuesta_subir_carpeta` | Paquetes de SUBIR CARPETA → clasifica bien |
| `test_clasificar_compuesta_sin_patron` | Multi-FileID sin patrón → OPERACION COMPLEJA |

### Tests de integración

| Test | Descripción |
|------|-------------|
| `test_v4_traza_user` | Pipeline completo con Traza_user_5.csv |
| `test_v4_traza_ransom` | Pipeline completo con Traza_ransom_formato_tabla.csv |
| `test_v4_comparativa` | Comparar resultados v2 vs v4 |

### Validación

Actualizar `validar_todas_operaciones.py` para que también pruebe el pipeline v4 completo (no solo `clasificar_operacion()` directa).

---

## 9. Criterios de éxito

- [ ] Las operaciones simples (1 FileID) se clasifican igual que en v2
- [ ] Las operaciones compuestas (múltiples FileIDs) se agrupan correctamente
- [ ] El clasificador de compuestas reconoce los patrones de la memoria TFG
- [ ] Los paquetes de asincronía sin CREATE propio se descartan
- [ ] Los paquetes de subordinados fuera de rango se incluyen
- [ ] El reporte muestra tanto operaciones simples como compuestas
- [ ] Todos los tests existentes siguen pasando
