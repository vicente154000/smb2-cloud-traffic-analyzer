# Analizador de Tráfico SMB2

Analizador de tráfico de red SMB2 que, a partir de capturas de Wireshark, identifica automáticamente las operaciones de usuario realizadas sobre un servicio de almacenamiento en la nube (OneDrive, Google Drive, Dropbox). El análisis se basa en el protocolo SMB2, utilizado por estos servicios para la sincronización de archivos entre el cliente local y el servidor remoto.

## Motivación

Los servicios de almacenamiento en la nube sincronizan archivos mediante SMB2, un protocolo de red que permite compartir recursos en redes Windows. Cada acción del usuario (subir un archivo, borrarlo, renombrarlo, crear una carpeta, etc.) se traduce en una secuencia de comandos SMB2: CREATE para abrir el archivo, READ/WRITE para transferir datos, SET_INFO para modificar atributos, CLOSE para cerrarlo.

El problema es que estas secuencias aparecen **entremezcladas** en la captura debido a la naturaleza asíncrona de SMB2: el cliente puede enviar múltiples solicitudes sin esperar la respuesta de cada una. Esto hace que los paquetes de distintas operaciones se solapen temporalmente, y que los CLOSE puedan llegar en distinto orden al de los CREATE.

Este analizador resuelve ese problema agrupando los paquetes por **FileID** (el identificador único que SMB2 asigna a cada archivo abierto), de forma que cada grupo contiene exactamente los comandos de una operación atómica.

## Arquitectura

El analizador se organiza en cuatro fases:

```
1. Lectura del CSV (leer_csv)
   - Abre el archivo exportado desde Wireshark
   - Salta las cabeceras (filas 1-15 con metadatos)
   - Extrae campos y crea objetos PaqueteSMB2
   - Filtra comandos de ruido (NEGOTIATE, SESSION_SETUP, etc.)
   - Devuelve lista de paquetes

2. Agrupamiento jerárquico (agrupar_por_operacion_v4)
   - Pre-escanéa los paquetes para identificar qué FileIDs tienen CLOSE
   - Agrupa por FileID siguiendo el ciclo CREATE+CLOSE
   - Detecta operaciones compuestas (varios FileIDs relacionados)
   - Extrae operaciones atómicas de las compuestas
   - Devuelve lista de OperacionCompuesta

3. Clasificación (clasificar_operacion / clasificar_operacion_compuesta)
   - Para cada operación, extrae características
   - Aplica reglas en cascada (de más específica a más genérica)
   - Asigna un tipo (SUBIR ARCHIVO, BORRAR, RENOMBRAR, etc.)

4. Reporte (generar_reporte_v4)
   - Lista todas las operaciones detectadas
   - Muestra resumen estadístico por tipo
```

### Estructuras de datos

**PaqueteSMB2**: Representa un paquete individual extraído del CSV. Almacena línea, comando, timestamp, tree_id, file_id, file_path, create_options, info_class, read_len, write_len, y si tiene error.

**Operacion**: Grupo de paquetes de un mismo FileID que forman una operación atómica. Mantiene contadores internos (num_creates, num_closes, num_reads, num_writes, num_setinfo, num_finds) y métricas (total_read, total_write, timestamp_inicio, timestamp_fin).

**OperacionCompuesta**: Puede ser simple (1 FileID) o compuesta (varios FileIDs que pertenecen a una misma acción de alto nivel, como "subir carpeta" o "modificar archivo con editor"). Contiene una operación raíz y una lista de sub-operaciones.

### Archivos del proyecto

| Archivo | Descripción |
|---------|-------------|
| [`src/analizador_smb2_v4.py`](src/analizador_smb2_v4.py) | Analizador principal (v4, versión actual) |
| [`src/analizador_smb2_v2.py`](src/analizador_smb2_v2.py) | Versión anterior con agrupamiento simple por FileID |
| [`src/analizador_smb2_v3.py`](src/analizador_smb2_v3.py) | Versión intermedia con agrupamiento por ventana global |
| [`src/analizador_smb2_v1.py`](src/analizador_smb2_v1.py) | Versión original con agrupamiento por ventana temporal |
| [`tests/test_integracion_v4.py`](tests/test_integracion_v4.py) | Tests de integración para v4 (22 tests) |
| [`tests/validar_pipeline_v4.py`](tests/validar_pipeline_v4.py) | Script de validación del pipeline completo (7 casos) |
| [`tests/helpers.py`](tests/helpers.py) | Funciones auxiliares compartidas para tests |

## El problema del agrupamiento SMB2

### FileID

En SMB2, cuando un cliente quiere acceder a un archivo, envía un comando `CREATE`. El servidor responde con un **FileID** único que identifica ese manejador (handle). Todos los comandos posteriores (`READ`, `WRITE`, `SET_INFO`, `CLOSE`) que operen sobre ese archivo usan el mismo FileID.

Cada comando CREATE genera un FileID diferente, incluso si se trata del mismo archivo físico. Una misma operación de usuario puede generar múltiples FileIDs.

### Agrupamiento por FileID (v2)

La estrategia de la v2 se basa en una idea clave: **cada operación de usuario empieza con un CREATE y termina con un CLOSE del mismo FileID**. El algoritmo separa los paquetes por FileID, los ordena por timestamp, y para cada FileID recorre secuencialmente: un CREATE inicia una operación, y se añaden paquetes hasta encontrar el CLOSE que la cierra.

Esto resuelve de forma natural el problema de la asincronía: aunque en la traza original los paquetes estén entremezclados, al separar por FileID cada secuencia queda limpia.

### Agrupamiento jerárquico (v4)

La v4 introduce una mejora significativa: en lugar de tratar cada FileID como una operación independiente, **detecta relaciones entre FileIDs** para reconstruir operaciones compuestas de alto nivel.

El algoritmo funciona así:

1. **Pre-escanéo**: Recorre todos los paquetes para identificar qué FileIDs tienen al menos un CLOSE. Los FileIDs sin CLOSE se descartan (son operaciones incompletas o ruido).

2. **Agrupamiento por FileID**: Para cada FileID con CLOSE, agrupa los paquetes siguiendo el ciclo CREATE+CLOSE, igual que en v2.

3. **Detección de compuestas**: Cuando una operación (raíz) contiene paquetes de otros FileIDs (subordinados), se fusionan en una `OperacionCompuesta`. Esto ocurre típicamente cuando:
   - Se abre una carpeta (CREATE raíz) y luego se abren archivos dentro de ella (CREATEs subordinados)
   - Un editor abre un archivo, lo lee, y luego crea un archivo temporal para escribir los cambios

4. **Extracción de atómicas**: De cada operación compuesta se extraen las operaciones atómicas individuales (una por FileID), que son las que se clasifican individualmente.

Esto permite:
- **Reconstruir acciones completas**: "modificar archivo" = bajar + modificar + subir, todo en una misma operación compuesta
- **Detectar operaciones multi-FileID**: copiar carpeta, comprimir archivo, comprimir carpeta
- **Mantener la clasificación atómica**: cada FileID sigue clasificándose individualmente con las 21 reglas

### Comandos SMB2 relevantes

| Comando | Descripción | Rol en la operación |
|---------|-------------|---------------------|
| `CREATE` | Abre o crea un archivo | Inicia toda operación, genera un FileID |
| `READ` | Lee datos del archivo | Descargar, copiar, modificar |
| `WRITE` | Escribe datos en el archivo | Subir, copiar, modificar |
| `CLOSE` | Cierra el archivo | Finaliza la operación |
| `SET_INFO` | Modifica atributos del archivo | Borrar, renombrar |
| `QUERY_DIRECTORY` | Lista el contenido de un directorio | Navegar, listar |
| `QUERY_INFO` | Consulta metadatos del archivo | Operación interna del sistema |

Los comandos de ruido (`NEGOTIATE`, `SESSION_SETUP`, `LOGOFF`, `TREE_CONNECT`, `TREE_DISCONNECT`, `ECHO`, `CANCEL`, `LOCK`, `IOCTL`, `CHANGE_NOTIFY`, `OPLOCK_BREAK`, `FLUSH`) se filtran y se ignoran.

## Clasificación de operaciones

Cada operación atómica (extraída de una operación compuesta) se clasifica según los comandos SMB2 que contiene. Las reglas se aplican en orden de prioridad, de más específica a más genérica. La primera que cumple las condiciones gana.

### Reglas atómicas (21 reglas)

| # | Tipo | Patrón SMB2 |
|---|------|-------------|
| 1 | LISTAR DIRECTORIO | CREATE + FIND* + CLOSE (sin READ, WRITE, SET_INFO) |
| 2 | CREAR CARPETA | CREATE (CreateOptions bit directorio) + CLOSE |
| 3 | CREAR ARCHIVO VACÍO | CREATE (sin bit directorio) + CLOSE |
| 4 | BORRAR ARCHIVO/CARPETA | CREATE + SET_INFO(InfoClass=0x0D) + CLOSE |
| 5 | RENOMBRAR/MOVER | CREATE + SET_INFO(InfoClass=0x0A) + CLOSE |
| 6 | SUBIR ARCHIVO | CREATE + WRITE* + CLOSE (sin READ, FIND) |
| 7 | BAJAR ARCHIVO | CREATE + READ* + CLOSE (sin WRITE, FIND) |
| 8 | SUBIR CARPETA | CREATE + FIND + WRITE* + CLOSE (num_creates >= 2) |
| 9 | BAJAR CARPETA | CREATE + FIND + READ* + CLOSE (num_creates >= 2) |
| 10 | COPIAR ARCHIVO (subida) | CREATE + SET_INFO + WRITE* + CLOSE |
| 11 | COPIAR ARCHIVO (descarga) | CREATE + READ* + CLOSE (nunca se alcanza, idéntica a regla 7) |
| 12 | COPIAR CARPETA | CREATE + FIND + READ + WRITE + CLOSE (num_creates >= 2) |
| 13 | COMPRIMIR ARCHIVO | CREATE + READ + WRITE + CLOSE (num_file_ids >= 2, SET_INFO AllocationInfo) |
| 14 | COMPRIMIR CARPETA | FIND + READ + WRITE + CREATE + CLOSE (num_file_ids >= 3) |
| 15 | MODIFICAR (editor) | CREATE + READ + WRITE + CLOSE (IOCTL, num_file_ids >= 2) |
| 16 | MODIFICAR (comando atómico) | CREATE + SET_INFO + WRITE + CLOSE (sin READ, FIND) |
| 17 | CONSULTAR METADATOS | Solo QUERY_INFO, sin CREATE/READ/WRITE |
| 18 | APERTURA EFÍMERA | CREATE + CLOSE sin E/S, SET_INFO ni FIND |
| 19 | OPERACIÓN COMPLEJA | CREATE + READ + WRITE + CLOSE (num_creates >= 3, sin FIND) |
| 20 | RUIDO / SIN OPERACIÓN | Sin CREATE, READ, WRITE ni FIND |
| 21 | DESCONOCIDA | Cualquier otra combinación no reconocida |

### Detectores de operaciones compuestas (7 detectores)

Además de las 21 reglas atómicas, la v4 incorpora detectores específicos para clasificar operaciones compuestas (multi-FileID):

| Detector | Descripción |
|----------|-------------|
| COPIAR CARPETA | CREATE raíz + FIND + múltiples CREATEs subordinados con READ+WRITE |
| COMPRIMIR ARCHIVO | CREATE raíz + CREATE subordinado con READ+WRITE + SET_INFO(AllocationInfo) |
| COMPRIMIR CARPETA | CREATE raíz + FIND + múltiples subordinados con READ+WRITE |
| MODIFICAR (editor) | CREATE raíz con READ + CREATE subordinado con WRITE + IOCTL |
| SUBIR CARPETA | CREATE raíz + FIND + múltiples subordinados con WRITE |
| BAJAR CARPETA | CREATE raíz + FIND + múltiples subordinados con READ |
| OPERACIÓN COMPLEJA | Varios CREATEs con READ+WRITE sin patrón claro |

### Códigos de información SET_INFO

| InfoClass | Nombre | Operación |
|-----------|--------|-----------|
| `0x0A` (10) | FileRenameInformation | Renombrar o mover el archivo |
| `0x0D` (13) | FileDispositionInformation | Borrar el archivo |
| `0x04` (4) | FileBasicInformation | Modificar atributos básicos |
| `0x13` (19) | FileAllocationInformation | Reservar espacio (compresión) |
| `0x14` (20) | FileEndOfFileInformation | Truncar al final (modificación atómica) |

## Validación y pruebas

### Tests automatizados (22 tests)

Los tests de integración para v4 cubren:

- **Pre-escanéo**: detección de FileIDs con CLOSE, FileIDs sin CLOSE, múltiples CLOSE para el mismo FileID
- **Agrupamiento v4**: operaciones simples (1 FileID), compuestas (2-3 FileIDs), operaciones independientes, paquetes fuera de FileIDs abiertos, QUERY_INFO integrado, orden cronológico
- **Extracción de atómicas**: extracción de operaciones simples y compuestas, con FINDs integrados
- **Clasificación de compuestas**: bajar carpeta, subir carpeta, comprimir archivo, operación compleja, operación simple no clasifica como compuesta
- **Reporte**: generación de reporte sin y con operaciones
- **CSV real**: lectura de traza real, agrupamiento produce operaciones

Ejecución:
```bash
python -m pytest tests/test_integracion_v4.py -v
```

### Script de validación del pipeline

El script [`tests/validar_pipeline_v4.py`](tests/validar_pipeline_v4.py) prueba el pipeline completo (lectura -> agrupamiento -> extracción -> clasificación) con 7 casos sintéticos que cubren los escenarios más importantes:

1. **Secuenciales**: operaciones simples que no se entremezclan
2. **Entremezcladas**: paquetes de distintas operaciones solapados temporalmente
3. **Copiar carpeta**: operación compuesta con múltiples FileIDs
4. **FINDs integrados**: QUERY_DIRECTORY asociado a la operación correcta
5. **CREATE sin CLOSE**: FileID abierto pero no cerrado (se descarta)
6. **FINDs fuera**: QUERY_DIRECTORY sin FileID asociado
7. **Reutilización de FileID**: mismo FileID usado en múltiples ciclos CREATE+CLOSE

Ejecución:
```bash
python tests/validar_pipeline_v4.py
```

## Resultados

### Traza de usuario (Traza_user_5.csv)

La traza contiene **26.817 paquetes SMB2** capturados durante una sesión normal de uso de OneDrive. El análisis con v4 produce:

| Tipo de operación | Cantidad | Porcentaje |
|-------------------|----------|------------|
| SUBIR ARCHIVO | 2.360 | 49,2% |
| BORRAR ARCHIVO | 1.180 | 24,6% |
| BAJAR ARCHIVO | 590 | 12,3% |
| RENOMBRAR/MOVER ARCHIVO | 590 | 12,3% |
| CREAR CARPETA | 32 | 0,7% |
| DESCONOCIDA | 41 | 0,9% |
| **Total** | **4.793** | **100%** |

El **99,1%** de las operaciones se clasifican correctamente. La operación más frecuente es SUBIR ARCHIVO (49,2%), coherente con un usuario que sincroniza archivos con la nube. Se observa un patrón de **BAJAR + SUBIR + RENOMBRAR + BORRAR** que corresponde a "reemplazar un archivo": el cliente descarga el original, renombra el antiguo, sube el nuevo y borra el renombrado.

### Traza de ransomware (Traza_ransom_formato_tabla.txt)

La traza contiene **26.742 paquetes SMB2** capturados durante un ataque de ransomware sobre una carpeta sincronizada con OneDrive. El análisis produce:

| Tipo de operación | Cantidad | Porcentaje |
|-------------------|----------|------------|
| CREAR ARCHIVO VACÍO | 2.897 | 54,1% |
| DESCONOCIDA | 1.152 | 21,5% |
| BORRAR ARCHIVO | 971 | 18,2% |
| RENOMBRAR/MOVER ARCHIVO | 298 | 5,6% |
| CREAR CARPETA | 32 | 0,6% |
| **Total** | **5.350** | **100%** |

El **78,5%** se clasifica correctamente. La operación más frecuente es CREAR ARCHIVO VACÍO (54,1%), que corresponde al ransomware creando archivos cifrados. No hay operaciones de SUBIR ARCHIVO ni BAJAR ARCHIVO (el ransomware no descarga ni sube a la nube). La tasa de DESCONOCIDA es del 21,5%, significativamente mayor que en la traza de usuario (0,9%).

### Comparativa usuario vs ransomware

| Aspecto | Usuario | Ransomware |
|---------|---------|------------|
| Paquetes totales | 26.817 | 26.742 |
| Operaciones totales | 4.793 | 5.350 |
| Clasificadas correctamente | 99,1% | 78,5% |
| DESCONOCIDA | 41 (0,9%) | 1.152 (21,5%) |
| Operación principal | SUBIR ARCHIVO (49,2%) | CREAR ARCHIVO VACÍO (54,1%) |
| SUBIR ARCHIVO | 2.360 | 0 |
| BAJAR ARCHIVO | 590 | 0 |
| BORRAR ARCHIVO | 1.180 | 971 |
| RENOMBRAR/MOVER | 590 | 298 |
| CREAR CARPETA | 32 | 32 |

### Operaciones compuestas detectadas (v4)

Sobre la traza de usuario, la v4 detecta **77 operaciones compuestas** (de las 4.793 operaciones totales), de las cuales se extraen **4.752 operaciones atómicas** (quedan 41 sin clasificar, las mismas DESCONOCIDA de v2). Las 77 compuestas incluyen casos de COPIAR CARPETA, MODIFICAR ARCHIVO (con editor), y SUBIR/BAJAR CARPETA que en v2 aparecían como operaciones separadas.

## Versiones

| Versión | Algoritmo | Estado |
|---------|-----------|--------|
| **v4** (actual) | Agrupamiento jerárquico con pre-escanéo de CLOSEs, detección de compuestas, extracción de atómicas | Producción |
| v3 | Agrupamiento por ventana global (experimental) | Referencia |
| v2 | Agrupamiento por FileID (CREATE+CLOSE) | Mantenido como referencia |
| v1 | Agrupamiento por ventana temporal | Histórico |

## Uso

```bash
python src/analizador_smb2_v4.py <ruta_al_csv>
```

Para generar solo el resumen (sin listar todas las operaciones):

```bash
python src/analizador_smb2_v4.py --resumen <ruta_al_csv>
```

Para activar logs de depuración:

```bash
python src/analizador_smb2_v4.py --debug <ruta_al_csv>
```

### Formato del CSV de entrada

El CSV debe exportarse desde Wireshark con las siguientes columnas (en cualquier orden):

- `frame.time_relative` — timestamp del paquete
- `smb2.cmd` — comando SMB2
- `smb2.nt_status` — código de error
- `smb2.tid` — Tree ID
- `smb2.file_id` — FileID
- `smb2.create_options` — opciones de creación
- `smb2.set_info.info_class` — clase de información
- `smb2.filename` — ruta del archivo

El analizador detecta automáticamente el formato (CSV con punto y coma, CSV con coma, o formato tabla de Wireshark).
