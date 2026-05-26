# Analisis del Analizador SMB2 v4 — Operaciones Simples y Compuestas

## Indice

1. [Introduccion](#1-introduccion)
2. [Problemas de las versiones anteriores](#2-problemas-de-las-versiones-anteriores)
   - [2.1 v1: Agrupamiento por ventana temporal](#21-v1-agrupamiento-por-ventana-temporal)
   - [2.2 v2: Agrupamiento por FileID (CREATE+CLOSE)](#22-v2-agrupamiento-por-fileid-createclose)
   - [2.3 v3: Agrupamiento por ventana global](#23-v3-agrupamiento-por-ventana-global)
   - [2.4 Clasificador de segundo nivel](#24-clasificador-de-segundo-nivel)
3. [El nuevo analizador v4](#3-el-nuevo-analizador-v4)
   - [3.1 Acuerdo con el profesor](#31-acuerdo-con-el-profesor)
   - [3.2 Arquitectura del pipeline v4](#32-arquitectura-del-pipeline-v4)
   - [3.3 Estructuras de datos](#33-estructuras-de-datos)
   - [3.4 Algoritmo de agrupacion jerarquica](#34-algoritmo-de-agrupacion-jerarquica)
   - [3.5 Extraccion de operaciones atomicas](#35-extraccion-de-operaciones-atomicas)
   - [3.6 Clasificador de operaciones compuestas](#36-clasificador-de-operaciones-compuestas)
   - [3.7 Integracion de FINDs en operaciones activas](#37-integracion-de-finds-en-operaciones-activas)
4. [Problemas encontrados durante el desarrollo](#4-problemas-encontrados-durante-el-desarrollo)
   - [4.1 Problema: CREATEs huerfanos sin CLOSE](#41-problema-creates-huerfanos-sin-close)
   - [4.2 Solucion: Pre-escaneo de FileIDs con CLOSE](#42-solucion-pre-escaneo-de-fileids-con-close)
   - [4.3 Analisis detallado de CREATEs sin CLOSE en salidaSemana.txt](#43-analisis-detallado-de-creates-sin-close-en-salidasemanatxt)
   - [4.4 Problema: FINDs con GUID cero en formato TXT](#44-problema-finds-con-guid-cero-en-formato-txt)
   - [4.5 Solucion: Deteccion de GUID cero en el lector TXT](#45-solucion-deteccion-de-guid-cero-en-el-lector-txt)
   - [4.6 Problema: Multi-formato de entrada (CSV y TXT)](#46-problema-multi-formato-de-entrada-csv-y-txt)
   - [4.7 Solucion: Deteccion automatica de formato](#47-solucion-deteccion-automatica-de-formato)
5. [Resultados con trazas reales](#5-resultados-con-trazas-reales)
   - [5.1 Traza de usuario (Traza_user_5.csv)](#51-traza-de-usuario-traza_user_5csv)
   - [5.2 Traza de ransomware (salidaSemana.txt)](#52-traza-de-ransomware-salidasemanatxt)
   - [5.3 Comparativa v2 vs v4](#53-comparativa-v2-vs-v4)
6. [Limitaciones y trabajo futuro](#6-limitaciones-y-trabajo-futuro)

---

## 1. Introduccion

Este documento recoge el proceso de desarrollo del **analizador SMB2 v4**, desde los problemas detectados en versiones anteriores hasta la implementacion final del nuevo algoritmo de agrupacion jerarquica. El objetivo es documentar tanto las decisiones de diseno como los problemas tecnicos encontrados, para que sirva como referencia en la redaccion de la memoria del TFG.

El codigo fuente del analizador v4 se encuentra en [`src/analizador_smb2_v4.py`](src/analizador_smb2_v4.py).

---

## 2. Problemas de las versiones anteriores

### 2.1 v1: Agrupamiento por ventana temporal

El primer analizador ([`src/analizador_smb2.py`](src/analizador_smb2.py)) agrupaba los paquetes usando una **ventana temporal de 2 segundos**: si dos paquetes consecutivos del mismo FileID/TreeID tenian una diferencia menor a 2 segundos, se consideraban parte de la misma operacion.

**Problemas detectados:**

1. **Falsa separacion por asincronia**: En SMB2, el cliente puede enviar multiples solicitudes sin esperar respuesta. Esto provoca que paquetes de la misma operacion lleguen separados por mas de 2 segundos (por ejemplo, si el servidor tarda en responder), fragmentando una operacion real en varias operaciones falsas.

2. **Falsa fusion por solapamiento**: Si dos operaciones distintas ocurren en menos de 2 segundos (algo muy frecuente en la sincronizacion con la nube), sus paquetes se fusionan en una sola operacion, mezclando comandos de diferentes acciones.

3. **Resultado**: 5.364 operaciones detectadas en la traza de usuario, muchas de ellas incorrectamente agrupadas. El umbral de 2 segundos era heuristico y no se adaptaba al comportamiento real del protocolo.

### 2.2 v2: Agrupamiento por FileID (CREATE+CLOSE)

El segundo analizador ([`src/analizador_smb2_v2.py`](src/analizador_smb2_v2.py)) cambio la estrategia: en lugar de ventana temporal, agrupa por **FileID** usando el par CREATE+CLOSE como delimitador. Cada FileID se procesa de forma independiente, lo que resuelve el problema de la asincronia.

**Problemas detectados:**

1. **Operaciones multi-FileID no detectadas**: Muchas operaciones de usuario generan **multiples FileIDs** (uno por cada archivo involucrado). Por ejemplo:
   - **COMPRIMIR ARCHIVO**: 2 FileIDs (original + comprimido)
   - **COMPRIMIR CARPETA**: 3+ FileIDs (carpeta + archivos + comprimido)
   - **COPIAR CARPETA**: 2+ FileIDs (carpeta origen + archivos destino)
   - **MODIFICAR ARCHIVO (editor)**: 2+ FileIDs (lectura + escritura)
   - **SUBIR/BAJAR CARPETA**: 2+ FileIDs (carpeta + archivos)

   Al separar por FileID, estas operaciones se fragmentan en operaciones atomicas independientes. Por ejemplo, "modificar archivo" se convierte en dos operaciones: "bajar archivo" + "subir archivo".

2. **Reglas 8-15 inalcanzables en la practica**: Las reglas del clasificador que requieren `num_creates >= 2` o `num_file_ids >= 2` (SUBIR CARPETA, BAJAR CARPETA, COPIAR CARPETA, COMPRIMIR ARCHIVO, COMPRIMIR CARPETA, MODIFICAR ARCHIVO) nunca se activan porque cada FileID se procesa por separado.

3. **FINDs sin FileID**: Los comandos `QUERY_DIRECTORY` (FIND) no tienen FileID, por lo que se procesan aparte con ventana temporal. Esto impide asociarlos correctamente con la operacion CREATE+CLOSE que los origina.

4. **Resultados**:
   - **Traza de usuario (Traza_user_5.csv)**: 4.793 operaciones atomicas, todas de 1 FileID. El 99,1% se clasifican correctamente (SUBIR ARCHIVO 2.360, BORRAR 1.180, BAJAR 590, RENOMBRAR 590, CREAR CARPETA 32, DESCONOCIDA 41). Ninguna operacion compuesta detectada.
   - **Traza de ransomware (Traza_ransom_formato_tabla.csv)**: 5.350 operaciones atomicas (CREAR ARCHIVO VACIO 2.897, DESCONOCIDA 1.152, BORRAR 971, RENOMBRAR 298, CREAR CARPETA 32). Ninguna operacion compuesta detectada.
   - **Traza de ransomware grande (salidaSemana.txt)**: No soportada (formato TXT incompatible con el lector CSV de v2).

### 2.3 v3: Agrupamiento por ventana global

El tercer analizador ([`src/analizador_smb2_v3.py`](src/analizador_smb2_v3.py)) fue un **experimento** para probar un enfoque radicalmente distinto: agrupar por ventana global sin separar por FileID. La idea era que el primer CREATE de la traza inicia una operacion, y todos los paquetes hasta el siguiente CLOSE (de cualquier FileID) pertenecen a esa operacion.

**Problemas detectados:**

1. **Solapamiento masivo de FileIDs**: En una traza real, los FileIDs de diferentes operaciones se solapan constantemente. Por ejemplo, mientras se esta cerrando el FileID de una operacion A, ya se esta abriendo el FileID de una operacion B. Al no separar por FileID, todos los paquetes se mezclan en una unica operacion gigante.

2. **Resultados inutilizables**:
   - Traza de usuario: solo 3 operaciones detectadas (una de ellas con 5.322 FileIDs)
   - Traza de ransomware: 1 unica operacion con los 26.742 paquetes

3. **Conclusion**: El enfoque de ventana global sin separacion por FileID no funciona porque los FileIDs de diferentes operaciones se entremezclan constantemente debido a la asincronia del protocolo.

### 2.4 Clasificador de segundo nivel

Antes de desarrollar la v4, se intento un enfoque intermedio: el **clasificador de segundo nivel** ([`src/clasificador_segundo_nivel.py`](src/clasificador_segundo_nivel.py)). La idea era tomar las operaciones atomicas de v2 y fusionarlas en operaciones compuestas mediante un post-procesado.

**Problemas detectados:**

1. **Fusion limitada**: Solo se detectaron 16 operaciones MODIFICAR ARCHIVO en la traza de usuario (de 4.793 atomicas). El resto no se pudo fusionar porque los criterios de cercania temporal y misma carpeta eran demasiado restrictivos o porque las operaciones atomicas no compartian suficiente contexto.

2. **Sin efecto en traza de ransomware**: En la traza de ransomware, 0 operaciones se fusionaron. El ransomware no sigue los patrones de "misma carpeta" o "cercania temporal" que el clasificador esperaba.

3. **Complejidad anadida**: El clasificador de segundo nivel duplicaba la logica de agrupacion, haciendo el sistema mas dificil de mantener y depurar.

4. **Conclusion**: El enfoque de post-procesado sobre operaciones atomicas no era suficiente. Se necesitaba un cambio en el algoritmo de agrupacion desde la raiz.

---

## 3. El nuevo analizador v4

### 3.1 Acuerdo con el profesor

Tras analizar las limitaciones de las versiones anteriores, se llego al siguiente acuerdo con el profesor sobre la arquitectura del nuevo analizador:

1. **Agrupar CREATE-CLOSE** con un algoritmo jerarquico: el primer CREATE de la traza es la "raiz" de una operacion compuesta. Cualquier CREATE que aparezca dentro del intervalo `[CREATE_raiz, CLOSE_raiz]` es un "subordinado" y pertenece a la misma operacion.

2. **Extraer operaciones atomicas** hijas de cada operacion compuesta (1 por FileID).

3. **Clasificar operaciones atomicas** reutilizando el clasificador de v2 (21 reglas en cascada).

4. **Clasificar operaciones compuestas** con un nuevo clasificador que opera sobre los paquetes raw (no sobre las atomicas), aplicando solo reglas multi-FileID.

5. **Integrar FINDs** dentro de la operacion activa si aparecen dentro del rango CREATE-CLOSE del raiz.

### 3.2 Arquitectura del pipeline v4

El pipeline de la v4 consta de 4 pasos:

```
1. Leer CSV/TXT (leer_csv)
   - Detectar formato automaticamente (CSV de Wireshark o TXT de salidaSemana)
   - Extraer paquetes SMB2
   - Filtrar comandos de ruido

2. Agrupar por operacion (agrupar_por_operacion_v4)
   - Pre-escanear FileIDs con CLOSE
   - Recorrer paquetes en orden cronologico
   - Primer CREATE con CLOSE -> raiz de OperacionCompuesta
   - CREATEs dentro del intervalo -> subordinados
   - FINDs sin FileID -> integrados en operacion activa
   - CLOSE del raiz -> cierra la operacion compuesta

3. Clasificar (por cada OperacionCompuesta)
   3a. Extraer operaciones atomicas (1 por FileID)
   3b. Clasificar cada atomica con clasificador de v2
   3c. Si es multi-FileID -> clasificar como compuesta

4. Generar reporte (generar_reporte_v4)
   - Listar todas las operaciones (simples y compuestas)
   - Mostrar resumen estadistico por tipo
```

### 3.3 Estructuras de datos

La v4 introduce una nueva clase [`OperacionCompuesta`](src/analizador_smb2_v4.py:160) que envuelve los paquetes de una operacion, ya sea simple (1 FileID) o compuesta (multiples FileIDs):

```python
class OperacionCompuesta:
    id: str                    # UUID unico
    fileid_raiz: str           # FileID del CREATE principal
    paquetes: List[PaqueteSMB2]  # Todos los paquetes en orden cronologico
    operaciones_atomicas: List[Operacion]  # Atomicas extraidas
    es_simple: bool            # True = 1 FileID, False = multiples
    tipo_atomica: str          # Clasificacion si es simple
    tipo_compuesta: str        # Clasificacion si es compuesta
```

La clase [`Operacion`](src/analizador_smb2_v4.py:85) existente se modifico para anadir el campo `id_compuesta`, que indica a que operacion compuesta pertenece cada atomica.

### 3.4 Algoritmo de agrupacion jerarquica

El corazon de la v4 es la funcion [`agrupar_por_operacion_v4()`](src/analizador_smb2_v4.py:606). El algoritmo funciona asi:

```
1. Pre-escanear todos los paquetes para identificar que FileIDs
   tienen al menos un CLOSE (fids_con_close).

2. Recorrer paquetes en orden cronologico:

   a. Si el paquete NO tiene FileID (QUERY_DIRECTORY, QUERY_INFO):
      - Si hay operacion activa -> integrar en ella
      - Si no -> guardar para agrupar al final por TreeID

   b. Si el paquete es un CREATE:
      - Si su FileID NO tiene CLOSE -> descartar (CREATE huerfano)
      - Si no hay operacion activa -> es el raiz, iniciar OperacionCompuesta
      - Si ya hay operacion activa:
        - Si es el mismo FileID que el raiz -> cerrar la actual y empezar nueva
        - Si no -> es un subordinado, anyadir a fids_abiertos

   c. Si el paquete es un CLOSE:
      - Si su FileID esta en fids_abiertos -> anyadir y eliminar de abiertos
      - Si es el CLOSE del raiz -> cerrar la operacion compuesta

   d. Cualquier otro comando (READ, WRITE, SET_INFO, etc.):
      - Si su FileID esta en fids_abiertos -> anyadir
      - Si no -> descartar

3. Si queda una operacion sin cerrar -> anyadirla igualmente
4. Procesar paquetes sin FileID restantes (agrupar por TreeID con ventana de 2s)
```

**Ejemplo visual:**

```
Paquetes cronologicos:
[CREATE FID_A]  <- raiz, inicia op_compuesta_1
  [QUERY_DIRECTORY]  <- FIND sin FileID, se integra en op_compuesta_1
  [READ FID_A]
  [CREATE FID_B]  <- subordinado, se anyade a fids_abiertos
  [SET_INFO FID_B]
  [WRITE FID_B]
  [CLOSE FID_B]  <- se cierra FID_B, pero op_compuesta_1 sigue abierta
  [READ FID_B]   <- FID_B ya cerrado, pero estaba en fids_abiertos_original -> se mete
  [CREATE FID_C]  <- otro subordinado
  [WRITE FID_C]
  [CLOSE FID_C]
[CLOSE FID_A]    <- se cierra el raiz -> op_compuesta_1 termina

Resultado: 1 OperacionCompuesta con 3 FileIDs (FID_A, FID_B, FID_C)
```

### 3.5 Extraccion de operaciones atomicas

La funcion [`extraer_operaciones_atomicas()`](src/analizador_smb2_v4.py:794) toma los paquetes de una operacion compuesta y los separa por FileID, creando una `Operacion` por cada uno. Cada operacion atomica se clasifica con el clasificador clasico de v2 ([`clasificar_operacion()`](src/analizador_smb2_v4.py:892)), que aplica las 21 reglas en cascada.

### 3.6 Clasificador de operaciones compuestas

La funcion [`clasificar_operacion_compuesta()`](src/analizador_smb2_v4.py:1274) opera directamente sobre los paquetes raw de la operacion compuesta. Solo se aplica si la operacion tiene 2 o mas FileIDs. Las reglas multi-FileID que implementa son:

| Funcion | Regla | Descripcion |
|---------|-------|-------------|
| `_es_copiar_carpeta()` | 12 | CREATE(carpeta) + FIND + READ + WRITE, >=2 FileIDs |
| `_es_comprimir_archivo()` | 13 | CREATE(archivo) + READ + CREATE + SET_INFO(0x13) + WRITE, exactamente 2 FileIDs |
| `_es_comprimir_carpeta()` | 14 | CREATE(carpeta) + FIND + READ + WRITE + SET_INFO(0x13), >=3 FileIDs |
| `_es_modificar_archivo_editor()` | 15 | CREATE + READ + WRITE + IOCTL, >=2 FileIDs |
| `_es_subir_carpeta()` | 8 | CREATE(carpeta) + FIND + WRITE (sin READ), >=2 FileIDs |
| `_es_bajar_carpeta()` | 9 | CREATE(carpeta) + FIND + READ (sin WRITE), >=2 FileIDs |
| `_es_operacion_compleja()` | 19 | CREATE + READ + WRITE + SET_INFO, >=3 creates |

Si ninguna regla coincide, se clasifica como `OPERACION COMPLEJA` (generico).

### 3.7 Integracion de FINDs en operaciones activas

En v2, los comandos `QUERY_DIRECTORY` (FIND) no tenian FileID y se procesaban aparte con ventana temporal. En v4, si un FIND aparece dentro del rango de una operacion activa (entre su CREATE raiz y su CLOSE raiz), se integra en ella. Esto permite clasificar correctamente operaciones como BAJAR CARPETA o SUBIR CARPETA que requieren FIND.

La integracion se realiza en [`agrupar_por_operacion_v4()`](src/analizador_smb2_v4.py:667-678):

```python
if not pkt.file_id:
    if op_actual is not None:
        # Hay operacion activa -> integrar el FIND
        op_actual.anyadir(pkt)
        finds_integrados += 1
    else:
        # No hay operacion activa -> guardar para agrupar al final
        grupos_sin_fid.append(pkt)
    continue
```

---

## 4. Problemas encontrados durante el desarrollo

### 4.1 Problema: CREATEs huerfanos sin CLOSE

**Contexto:** Al ejecutar la v4 por primera vez sobre la traza de usuario (26.817 paquetes), solo se detectaron **10 operaciones compuestas**. El resto de los paquetes quedaban atrapados en una unica operacion gigante.

**Causa raiz:** El primer CREATE de la traza tenia un FileID (`dd0000000000000009000000ffffffff`) que **nunca se cerraba** (no tenia CLOSE en toda la traza). Como el algoritmo considera que el primer CREATE es el "raiz", y ese raiz nunca se cerraba, la operacion compuesta capturaba todos los paquetes desde la linea 37 hasta la linea 26.839 (25.580 paquetes, 4.758 FileIDs).

Este CREATE sin CLOSE es un **CREATE huerfano**: el sistema operativo abrio un archivo pero nunca lo cerro (o el CLOSE quedo fuera de la ventana de captura de Wireshark).

**Impacto:** El algoritmo quedaba bloqueado en una unica operacion que englobaba practicamente toda la traza, haciendo imposible cualquier clasificacion util.

### 4.2 Solucion: Pre-escaneo de FileIDs con CLOSE

**Solucion:** Se anadio una fase de **pre-escaneo** ([`_pre_escanear_fids_con_close()`](src/analizador_smb2_v4.py:591)) que recorre todos los paquetes antes del agrupamiento para identificar que FileIDs tienen al menos un CLOSE. Solo los CREATEs con FileID que tiene CLOSE confirmado pueden ser raiz de una operacion compuesta.

```python
def _pre_escanear_fids_con_close(paquetes):
    fids_con_close = set()
    for pkt in paquetes:
        if pkt.file_id and pkt.comando == "CLOSE":
            fids_con_close.add(pkt.file_id)
    return fids_con_close
```

Luego, en el algoritmo de agrupacion:

```python
if pkt.comando == "CREATE":
    if pkt.file_id not in fids_con_close:
        # CREATE sin CLOSE -> descartar (huerfano/muerto)
        continue
    # ... resto del algoritmo
```

**Resultado:** Con el pre-escaneo, los CREATEs huerfanos se descartan y solo los FileIDs con ciclo CREATE+CLOSE completo forman operaciones. En la traza de usuario se detectaron **77 operaciones** (61 simples + 16 compuestas), y en la traza de ransomware grande (salidaSemana.txt) se detectaron **15.458 operaciones** (9.842 simples + 1.523 compuestas).

Las metricas de descarte del pre-escaneo en cada traza son:

| Traza | Paquetes totales | FileIDs con CREATE | FileIDs con CLOSE | Descartados | % descarte |
|------|-----------------|-------------------|-------------------|-------------|-----------|
| Traza_user_5.csv | 26.817 | 4.760 | 4.752 | **8** | **0,17%** |
| salidaSemana.txt | 17.180.581 | 3.294.444 | 3.205.546 | **88.903** | **2,70%** |

En la traza de usuario el descarte es minimo (8 FileIDs, 0,17%), lo que indica una captura completa. En la traza de ransomware grande el descarte es mayor (88.903, 2,70%), pero como se analiza en la seccion siguiente, se debe a un problema de captura incompleta y no a comportamiento anomalo.

### 4.3 Analisis detallado de CREATEs sin CLOSE en salidaSemana.txt

**Contexto:** En la traza de ransomware grande (`salidaSemana.txt`, 17.2M paquetes), el pre-escaneo descarta **88.903 FileIDs** (2,70% del total de 3.294.444 FileIDs con CREATE). Se realizo un analisis profundo para determinar si estos FileIDs sin CLOSE siguen patrones comunes que permitan distinguir entre descartes por captura incompleta y posibles indicadores de comportamiento anomalo.

**Metricas globales:**

| Metrica | Valor |
|---------|-------|
| Total paquetes CREATE | 3.298.115 |
| FileIDs unicos con CREATE | 3.294.444 |
| FileIDs unicos con CLOSE | 3.205.546 |
| FileIDs sin CLOSE | **88.903 (2,70%)** |
| Rango temporal total | 698.354s (194h = ~8 dias) |

**Distribucion temporal:**

| Rango | FileIDs sin CLOSE |
|-------|-------------------|
| Dia 1 (0-24h) | 0 |
| Dia 2 (24-48h) | 0 |
| Dia 3 (48-72h) | 0 |
| Dia 4 (72-96h) | 0 |
| Dia 5 (96-120h) | 0 |
| Dia 6 (120-144h) | 0 |
| **Dia 7+ (144h+)** | **88.903 (100%)** |

**Hallazgo critico:** El **100% de los FileIDs sin CLOSE** aparecen en el **Dia 7+** (mas alla de 144 horas desde el inicio de la captura). La traza dura 194 horas (~8 dias), y todos los FileIDs sin CLOSE se concentran en el ultimo dia. Esto sugiere fuertemente que la causa es un **problema de captura incompleta**: el CLOSE de estos FileIDs ocurrio despues de que terminara la ventana de captura, no porque el ransomware los dejara abiertos intencionadamente.

**Distribucion por TreeID (Top 10):**

| TreeID | FileIDs sin CLOSE | % |
|--------|-------------------|---|
| 1 | 85.386 | **96,0%** |
| 5 | 2.244 | 2,5% |
| 9 | 605 | 0,7% |
| 0 | 350 | 0,4% |
| 13 | 310 | 0,3% |
| 17 | 142 | 0,2% |
| 21 | 67 | 0,1% |
| 25 | 27 | <0,1% |
| 37 | 15 | <0,1% |
| 33 | 13 | <0,1% |

**Hallazgo:** El **96% de los FileIDs sin CLOSE** pertenecen al **TreeID 1**. Esto indica que un unico share/conexion SMB2 (TreeID 1) concentra casi todos los descartes, lo que refuerza la hipotesis de captura incompleta: el TreeID 1 probablemente corresponde a un share que se uso intensamente al final de la semana y cuyos CLOSE quedaron fuera de la ventana de captura.

**Actividad de los FileIDs sin CLOSE:**

| Tipo de actividad | Cantidad |
|-------------------|----------|
| Solo CREATE (0 actividad) | 22.606 (25,4%) |
| Con READ | 54.428 (61,2%) |
| Con WRITE | 14.278 (16,1%) |
| Con SET_INFO | 16.201 (18,2%) |

**Interpretacion:** El 74,6% de los FileIDs sin CLOSE tienen **actividad real** (READ, WRITE, SET_INFO). No son simplemente CREATEs fallidos o aperturas sin uso. Esto significa que el servidor SMB2 estaba procesando operaciones sobre estos archivos (leyendo, escribiendo, modificando metadatos) pero el CLOSE nunca llego a capturarse.

**Casos extremos (Top 5 FileIDs sin CLOSE con mas paquetes):**

| FileID | Paquetes | Comandos | Duracion | TreeID |
|--------|----------|----------|----------|--------|
| fid_1 | 13.164 | Solo READ | 31,3s | 29 |
| fid_2 | 9.999 | Solo READ | 60,6s | 9 |
| fid_3 | 9.716 | Solo READ | 21,0s | 5 |
| fid_4 | 9.518 | Solo WRITE | 7,9s | 1 |
| fid_5 | 9.158 | Solo READ | 20,1s | 9 |

**Casos con larga duracion sin CLOSE:**

| FileID | Paquetes | Comandos | Duracion | TreeID |
|--------|----------|----------|----------|--------|
| fid_A | 4.601 | READ+SET_INFO+WRITE | **6.097s (1,7h)** | 1 |
| fid_B | 3.551 | READ+SET_INFO+WRITE | **4.933s (1,4h)** | 1 |
| fid_C | 3.422 | READ+SET_INFO+WRITE | **3.846s (1,1h)** | 1 |
| fid_D | 4.941 | READ+SET_INFO+WRITE | **2.942s (0,8h)** | 1 |

**Interpretacion:** Existen casos donde un FileID permanece abierto **mas de una hora** con actividad continua (READ+SET_INFO+WRITE) sin que se capture su CLOSE. Esto es inusual para operaciones normales de usuario, pero en el contexto de la traza (todos en Dia 7+, 96% en TreeID 1), es mas probable que el CLOSE quedara fuera de la ventana de captura que un comportamiento deliberado del ransomware.

**Verificacion de borde de captura:**

| Metrica | Valor |
|---------|-------|
| FileIDs sin CLOSE que empiezan en el ultimo 1% de la traza | **8** |
| FileIDs sin CLOSE que terminan en el primer 1% de la traza | **8** |

**Conclusion:** Solo **8 FileIDs** de los 88.903 comienzan en el ultimo 1% del tiempo de la traza (donde seria esperable que no tuvieran CLOSE por estar al final). El resto (88.895) empiezan mucho antes y simplemente nunca recibieron CLOSE. Esto, junto con la concentracion en Dia 7+ y TreeID 1, confirma que el problema es de **captura incompleta** y no de comportamiento anomalo del ransomware.

**Implicacion para el analizador:** El pre-escaneo descarta correctamente estos 88.903 FileIDs (2,70% del total), evitando que distorsionen el agrupamiento. El porcentaje de descarte es aceptable y no afecta significativamente a los resultados. En la traza de usuario (Traza_user_5.csv), solo se descartan **8 FileIDs** (0,55% de los paquetes), lo que confirma que en capturas completas el descarte es minimo.

### 4.4 Problema: FINDs con GUID cero en formato TXT

**Contexto:** Al integrar los FINDs en las operaciones activas, se observo que **ningun FIND se integraba** en la traza de ransomware (`salidaSemana.txt`), a pesar de que habia 869.750 comandos QUERY_DIRECTORY en la traza.

**Causa raiz:** En el formato TXT de `salidaSemana.txt`, los comandos QUERY_DIRECTORY tenian un FileID con valor `00000000000000000000000000000000` (un GUID de 128 bits todo ceros). En el lector TXT ([`_leer_txt_formato()`](src/analizador_smb2_v4.py:399)), la condicion para detectar si un FileID estaba presente era:

```python
file_id = None
raw = partes[14] if len(partes) > 14 else ""
if raw and raw != "0":
    file_id = raw
```

El problema es que `"00000000000000000000000000000000"` es **truthy** (una cadena no vacia) y **no es igual a `"0"`**, por lo que el lector asignaba este GUID cero como FileID del paquete. Al tener FileID, el paquete no entraba en el bloque `if not pkt.file_id:` del algoritmo de agrupacion, y por tanto no se integraba en la operacion activa.

**Impacto:** 869.750 comandos QUERY_DIRECTORY quedaban fuera de las operaciones compuestas, lo que impedia clasificar correctamente operaciones como BAJAR CARPETA o SUBIR CARPETA que requieren FIND.

### 4.5 Solucion: Deteccion de GUID cero en el lector TXT

**Solucion:** Se anadio una comprobacion adicional en el lector TXT para detectar el GUID cero:

```python
if raw and raw != "0" and raw != "00000000000000000000000000000000":
    file_id = raw
```

**Resultado:** Tras la correccion:
- **Traza de ransomware (salidaSemana.txt)**: 2.572.008 paquetes sin FileID integrados en operaciones activas (869.750 QUERY_DIRECTORY + 805.182 QUERY_INFO + otros). El 100% de los QUERY_DIRECTORY que estaban dentro del rango de una operacion activa se integraron correctamente.
- **Traza de usuario (Traza_user_5.csv)**: 633 paquetes sin FileID integrados (el 100% de los QUERY_DIRECTORY dentro de operaciones activas).
- Las operaciones compuestas ahora incluyen correctamente los FINDs, permitiendo su clasificacion como BAJAR CARPETA, SUBIR CARPETA, COPIAR CARPETA, etc.

### 4.6 Problema: Multi-formato de entrada (CSV y TXT)

**Contexto:** El proyecto trabaja con dos formatos de entrada diferentes:
1. **CSV de Wireshark** (formato tabla exportado): usado para `Traza_user_5.csv` y `Traza_ransom_formato_tabla.csv`
2. **TXT de salidaSemana**: un formato espacio-separado con 20+ columnas, generado por una herramienta de captura diferente

Cada formato tiene:
- Distinto separador (`,` o `;` para CSV, espacios para TXT)
- Distinto numero de columnas (20 para CSV, 20+ para TXT)
- Distinta codificacion (UTF-8 con BOM para CSV, latin-1 para TXT)
- Distintas cabeceras (16 filas de metadatos para CSV, 1 linea de cabecera para TXT)
- Distinto orden de columnas

### 4.7 Solucion: Deteccion automatica de formato

**Solucion:** Se implemento una funcion [`_detectar_formato()`](src/analizador_smb2_v4.py:220) que analiza las primeras lineas del archivo para determinar el formato:

```python
def _detectar_formato(ruta):
    with open(ruta, "r", encoding="utf-8-sig", errors="replace") as f:
        primeras = [f.readline() for _ in range(5)]
    
    # Si la primera linea contiene "frame.time_relative" -> CSV de Wireshark
    if any("frame.time" in linea for linea in primeras):
        return "csv"
    
    # Si la primera linea contiene "SourceIP" -> TXT de salidaSemana
    if any("SourceIP" in linea for linea in primeras):
        return "txt"
    
    # Si hay punto y coma en las primeras lineas -> CSV
    if any(";" in linea for linea in primeras):
        return "csv"
    
    return "csv"  # por defecto
```

Luego, la funcion [`leer_csv()`](src/analizador_smb2_v4.py:555) redirige al lector adecuado segun el formato detectado.

---

## 5. Resultados con trazas reales

### 5.1 Traza de usuario (Traza_user_5.csv)

**Configuracion:** 26.817 paquetes SMB2, formato CSV de Wireshark. Traza de actividad de usuario real sincronizando archivos con la nube (Dropbox/OneDrive).

**Resultados v2:**

| Tipo | Total |
|------|-------|
| SUBIR ARCHIVO | 2.360 |
| BORRAR ARCHIVO | 1.180 |
| BAJAR ARCHIVO | 590 |
| RENOMBRAR/MOVER ARCHIVO | 590 |
| DESCONOCIDA | 41 |
| CREAR CARPETA | 32 |
| **Total** | **4.793** |

**Resultados v4:**

| Tipo | Simples | Compuestas | Total |
|------|---------|------------|-------|
| SUBIR ARCHIVO | 27 | - | 27 |
| BORRAR ARCHIVO | 18 | - | 18 |
| RENOMBRAR/MOVER ARCHIVO | 9 | - | 9 |
| CREAR CARPETA | 2 | - | 2 |
| COPIAR CARPETA | - | 7 | 7 |
| OPERACION COMPLEJA | - | 9 | 9 |
| SIN CLASIFICAR | 5 | - | 5 |
| **Total** | **61** | **16** | **77** |

**Interpretacion:**
- La v4 detecta **77 operaciones** frente a las 4.793 atomicas de v2. Esta reduccion es esperada y correcta: la v4 agrupa por jerarquia de FileIDs (raiz + subordinados), no por FileID individual.
- Cada operacion compuesta en v4 engloba multiples operaciones atomicas de v2. Por ejemplo, una operacion "COPIAR CARPETA" en v4 contiene decenas de SUBIR ARCHIVO, BORRAR ARCHIVO, etc. como sub-operaciones.
- Se detectan **16 operaciones compuestas** que v2 no podia detectar:
  - 7 COPIAR CARPETA (multi-FileID con FIND + READ + WRITE)
  - 9 OPERACION COMPLEJA (multi-FileID sin patron especifico reconocido)
- Las 61 operaciones simples (1 FileID) se clasifican correctamente como SUBIR, BORRAR, RENOMBRAR, CREAR CARPETA.
- 5 operaciones simples quedan SIN CLASIFICAR (no coinciden con ninguna regla atomica).

### 5.2 Traza de ransomware (Traza_ransom_formato_tabla.csv)

**Configuracion:** 26.742 paquetes SMB2, formato CSV de Wireshark. Traza de ransomware cifrando archivos en una carpeta compartida.

**Resultados v2:**

| Tipo | Total |
|------|-------|
| CREAR ARCHIVO VACIO | 2.897 |
| DESCONOCIDA | 1.152 |
| BORRAR ARCHIVO | 971 |
| RENOMBRAR/MOVER ARCHIVO | 298 |
| CREAR CARPETA | 32 |
| **Total** | **5.350** |

**Resultados v4:**

| Tipo | Simples | Compuestas | Total |
|------|---------|------------|-------|
| CREAR ARCHIVO VACIO | 26 | - | 26 |
| BORRAR ARCHIVO | 16 | - | 16 |
| RENOMBRAR/MOVER ARCHIVO | 5 | - | 5 |
| CREAR CARPETA | 2 | - | 2 |
| OPERACION COMPLEJA | - | 16 | 16 |
| **Total** | **49** | **16** | **65** |

**Interpretacion:**
- La v4 detecta **65 operaciones compuestas** frente a las 5.350 atomicas de v2. La reduccion es aun mas drastica que en la traza de usuario porque el ransomware genera muchos FileIDs sin CLOSE (1.152 CREATEs descartados por el pre-escaneo).
- Las 16 operaciones compuestas se clasifican todas como OPERACION COMPLEJA (generico), lo que indica que el ransomware no sigue los patrones de usuario (COPIAR CARPETA, BAJAR CARPETA, etc.) que el clasificador de compuestas reconoce.
- Las 49 operaciones simples se clasifican correctamente como CREAR ARCHIVO VACIO, BORRAR, RENOMBRAR, CREAR CARPETA.

### 5.3 Traza grande (salidaSemana.txt)

**Configuracion:** 17.180.581 paquetes SMB2, formato TXT espacio-separado. Traza de una semana completa de actividad de ransomware en un servidor de archivos.

**Resultados v4:**

| Tipo | Simples | Compuestas | Total |
|------|---------|------------|-------|
| CREAR ARCHIVO VACIO | 6.099 | - | 6.099 |
| DESCONOCIDA | 2.872 | - | 2.872 |
| SUBIR ARCHIVO | 562 | - | 562 |
| CREAR CARPETA | 271 | - | 271 |
| BAJAR ARCHIVO | 38 | - | 38 |
| OPERACION COMPLEJA | - | 850 | 850 |
| OPERACION COMPLEJA (modif masiva) | - | 471 | 471 |
| COPIAR CARPETA | - | 138 | 138 |
| BAJAR CARPETA | - | 56 | 56 |
| SUBIR CARPETA | - | 8 | 8 |
| **Total** | **9.842** | **1.523** | **15.458** |

**Interpretacion:**
- Se detectan **15.458 operaciones** en total (9.842 simples + 1.523 compuestas).
- La operacion simple mas frecuente es CREAR ARCHIVO VACIO (6.099, 39%), consistente con el comportamiento de ransomware que crea archivos cifrados.
- Hay 2.872 operaciones DESCONOCIDA (19%), que corresponden a patrones no reconocidos por las 21 reglas del clasificador atomico.
- Se detectan **1.523 operaciones compuestas**:
  - 850 OPERACION COMPLEJA (generico, multi-FileID sin patron especifico)
  - 471 OPERACION COMPLEJA (modif masiva) — operaciones con SET_INFO + WRITE en multiples archivos
  - 138 COPIAR CARPETA — el ransomware duplica estructuras de carpetas
  - 56 BAJAR CARPETA — el ransomware lee carpetas completas (posiblemente para enumerar archivos antes de cifrar)
  - 8 SUBIR CARPETA — subida de estructuras de carpetas
- Se integraron **2.572.008 FINDs/QUERY_INFO** dentro de operaciones activas, lo que permite clasificar correctamente las operaciones que requieren FIND (BAJAR CARPETA, SUBIR CARPETA, COPIAR CARPETA).

### 5.4 Comparativa v2 vs v4

| Aspecto | v2 | v4 |
|---------|----|----|
| Algoritmo de agrupacion | Por FileID (CREATE+CLOSE) | Jerarquico (raiz/subordinados) |
| Operaciones atomicas | Si (1 por FileID) | Si (extraidas de cada compuesta) |
| Operaciones compuestas | No detectadas | Si (multi-FileID) |
| FINDs | Procesados aparte (ventana temporal) | Integrados en operacion activa |
| Traza usuario (total ops) | 4.793 atomicas | 77 compuestas (61 simples + 16 multi-FileID) |
| Traza ransomware pequena (total ops) | 5.350 atomicas | 65 compuestas (49 simples + 16 multi-FileID) |
| Traza ransomware grande (total ops) | No soportada (formato TXT) | 15.458 compuestas (9.842 simples + 1.523 multi-FileID) |
| Soporte multi-formato | Solo CSV | CSV + TXT (auto-deteccion) |
| CREATEs sin CLOSE | Incluidos como operaciones | Descartados (pre-escaneo) |

**Nota importante sobre la comparativa:** La v4 no produce "menos" operaciones que v2, sino que las agrupa de forma diferente. En v2, cada FileID genera una operacion atomica independiente (4.793 en traza de usuario). En v4, los FileIDs se agrupan por jerarquia (raiz + subordinados), produciendo 77 operaciones compuestas en la misma traza. Cada operacion compuesta de v4 contiene multiples operaciones atomicas de v2 como sub-operaciones. Por tanto, **no son directamente comparables en numero**: v4 ofrece una vision mas abstracta (operaciones de alto nivel como "COPIAR CARPETA"), mientras que v2 ofrece una vision granular (operaciones atomicas como "SUBIR ARCHIVO", "BORRAR ARCHIVO").

**Conclusion:** La v4 introduce la capacidad de detectar operaciones compuestas multi-FileID que v2 no podia identificar. En la traza de ransomware grande (salidaSemana.txt), se detectan 1.523 operaciones compuestas, incluyendo patrones como COPIAR CARPETA (138), BAJAR CARPETA (56) y SUBIR CARPETA (8). La integracion de FINDs permite clasificar correctamente estas operaciones. Sin embargo, el clasificador de compuestas aun deja 850 operaciones como OPERACION COMPLEJA generico (56%), lo que indica que se necesitan mas reglas para cubrir todos los patrones.

---

## 6. Limitaciones y trabajo futuro

### 6.1 Limitaciones actuales

1. **Clasificador de compuestas limitado**: Aunque se detectan 1.523 operaciones compuestas en la traza de ransomware grande (salidaSemana.txt), 850 de ellas (56%) quedan sin patron reconocido (OPERACION COMPLEJA generico). Se necesitan mas reglas para cubrir estos casos.

2. **Dependencia del pre-escaneo**: El pre-escaneo de FileIDs con CLOSE requiere recorrer toda la traza dos veces (una para el pre-escaneo, otra para el agrupamiento). Para trazas muy grandes (17 millones de paquetes), esto duplica el tiempo de procesamiento.

3. **FINDs fuera de operacion**: Los FINDs que aparecen fuera de cualquier operacion activa se siguen agrupando por TreeID con ventana temporal (igual que v2). Esto puede dejar FINDs huerfanos sin asociar a ninguna operacion.

4. **Soporte de formatos**: Aunque se anadio soporte para TXT, el formato ODS (usado en algunas trazas) no se soporta directamente. Requiere conversion manual a CSV.

### 6.2 Trabajo futuro

1. **Ampliar reglas del clasificador de compuestas**: Analizar las 850 operaciones compuestas sin patron (OPERACION COMPLEJA generico) para identificar nuevos patrones y anadir reglas.

2. **Optimizar el pre-escaneo**: En lugar de recorrer toda la traza dos veces, se podria hacer el pre-escaneo en una sola pasada mientras se agrupa, usando una ventana deslizante.

3. **Clasificador binario ransomware/usuario**: Usar las operaciones detectadas (simples y compuestas) como caracteristicas para un clasificador que distinga entre trafico legitimo y malicioso.

4. **Soporte para ODS**: Anadir un lector de archivos ODS (formato OpenDocument Spreadsheet) para evitar la conversion manual.

5. **Visualizacion temporal**: Generar graficos con la distribucion temporal de las operaciones para identificar patrones de comportamiento visualmente.
