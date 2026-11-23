# SecureWatch – Semana 10: identificación de software vulnerable (API NVD 2.0)

> *This product uses the NVD API but is not endorsed or certified by the NVD.*

## 1. Archivos de esta entrega

| Archivo | Qué es |
|---|---|
| `identificacion.py` | **Nuevo.** Módulo de identificación: normaliza el inventario, busca el CPE, consulta los CVE en la NVD, compara versiones y genera `vulnerabilidades.json`. |
| `main.py` | Agente actualizado (sustituye al de la Semana 9). Nuevo flag `--identificar`. |
| `server.py` | Servidor actualizado (sustituye al de la Semana 9). Nuevos endpoints `/api/vulnerabilidades`. |
| `test_identificacion.py` | Tests automáticos (no llaman a la API real). |
| `fixtures/` | Respuestas **reales** de la NVD descargadas el 23/11/2026, usadas por los tests. |
| `cpe_manual.json.ejemplo` | Ejemplo para fijar a mano el CPE de un programa. |
| `arrancar_agente_identificar.ps1` | Arranca el agente con `--identificar` usando el Python de Spyder. |

Copia todos los archivos en la **misma carpeta** que el resto del proyecto (donde están `equipo.json`, `software.json`, etc.), sustituyendo `main.py` y `server.py`.

## 2. Dependencias nuevas

Solo hay una dependencia nueva: **`packaging`** (comparación correcta de versiones). `requests`, `fastapi` y `uvicorn` ya se usaban. `pytest` es opcional (los tests también funcionan con `unittest`).

Con el Python de Spyder (PowerShell):

```powershell
$PY = Join-Path $env:LOCALAPPDATA "spyder-6\envs\spyder-runtime\python.exe"
& $PY -m pip install packaging requests fastapi uvicorn pytest
```

O desde la consola de Spyder / Anaconda Prompt:

```
python -m pip install packaging pytest
```

## 3. API Key de la NVD (opcional, recomendada)

Sin clave el programa funciona igual, pero la NVD solo permite **5 peticiones cada 30 s**, así que el módulo espera **6 s** entre peticiones. Con clave el límite es **50 cada 30 s** y espera solo **0,6 s**. Con el inventario actual (26 programas con versión) son unas 45-55 peticiones: unos **5 minutos sin clave** y menos de 1 minuto con clave.

### 3.1 Cómo rellenar el formulario (https://nvd.nist.gov/developers/request-an-api-key)

1. **Organization Name**: tu centro de estudios o tu nombre (p. ej. el nombre de tu universidad/instituto).
2. **Email Address**: un correo al que tengas acceso (llegará el enlace de activación).
3. **Organization Type**: **Academia** (es un proyecto de clase). *Personal Use / Not Listed* también es válido.
4. Haz **scroll hasta el final** del cuadro *Terms of Use* (si no llegas al final, la casilla no se activa) y marca **"I agree to the Terms of Use"**.
5. Pulsa **Submit**.
6. Abre el correo de la NVD y pulsa el **enlace de un solo uso** para activar y ver la clave. **Caduca a los 7 días**: si no lo activas, hay que pedir otra.
7. Copia la clave (formato `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`). Es personal: **no la compartas ni la subas al repositorio**.

### 3.2 Configurar la clave en Windows

La clave **no se escribe en el código**: se lee de la variable de entorno `NVD_API_KEY` y se envía en la cabecera HTTP `apiKey`.

- Solo para la sesión actual de PowerShell:
  ```powershell
  $env:NVD_API_KEY = "TU-CLAVE-AQUI"
  ```
- Permanente para tu usuario (cierra y vuelve a abrir PowerShell/Spyder después):
  ```powershell
  setx NVD_API_KEY "TU-CLAVE-AQUI"
  ```
- En `cmd` (para los `.bat`): `set NVD_API_KEY=TU-CLAVE-AQUI`
- En la consola de Spyder (solo esa sesión): `import os; os.environ["NVD_API_KEY"] = "TU-CLAVE-AQUI"`

Al ejecutar verás `consulta NVD con API key` o `sin API key (6 s entre peticiones)`.

## 4. Uso

```powershell
# Solo identificación (genera vulnerabilidades.json y muestra el resumen)
python identificacion.py
python identificacion.py --max 5        # prueba rápida con 5 programas
python identificacion.py --sin-cache    # ignora la caché local

# Agente completo: análisis + identificación + informe + HEARTBEAT
python main.py --identificar

# Identificación + un único envío y termina (como --solo-informe de la semana 8)
python main.py --identificar --solo-informe

# Sin --identificar el agente se comporta exactamente igual que en la Semana 9
python main.py --solo-informe
```

Con `--identificar`, `main.py`:
1. Genera `alertas.json` como siempre.
2. Llama a `analizar_vulnerabilidades()` → `vulnerabilidades.json`.
3. Envía el informe completo a `POST /api/equipos` con la nueva clave `"vulnerabilidades"` (versión **compacta**: resumen + CVE afectados/indeterminados con su CVSS, para que `registros.json` no crezca sin control).
4. Envía `vulnerabilidades.json` **completo** a `POST /api/vulnerabilidades`.
5. Continúa con el HEARTBEAT (salvo `--solo-informe`).

Si la NVD no responde, el programa afectado queda como `ERROR_NVD` y el agente **sigue funcionando**.

Las respuestas de la NVD se guardan 24 h en `nvd_cache.json` para no repetir consultas si se vuelve a ejecutar.

### Servidor

```powershell
python -m uvicorn server:app --host 0.0.0.0 --port 8000
```

| Método | Ruta | Descripción |
|---|---|---|
| POST | `/api/vulnerabilidades` | Recibe `vulnerabilidades.json` (obligatorio el campo `equipo`). Responde 201. Sustituye el informe anterior del mismo equipo. |
| GET | `/api/vulnerabilidades` | Lista el último informe de cada equipo. |
| GET | `/api/vulnerabilidades/{equipo}` | Informe de un equipo (404 si no existe). |

Se guardan en `vulnerabilidades.json` del servidor (diccionario por nombre de equipo, escritura atómica y `threading.Lock`). Los endpoints de las semanas 8 y 9 no cambian. Documentación interactiva: http://127.0.0.1:8000/docs

## 5. Cómo funciona la identificación

1. **Normalización** de `software.json`: se descartan las entradas sin versión, se limpian los nombres (`"WinRAR 7.13 (64-bit)"` → `WinRAR`, `"Spyder 6"` → `Spyder`, `" - en-us"` fuera), se limpia la versión (`"7.2.0 (48358)"` → `7.2.0`) y se eliminan duplicados (mismo nombre + versión).
2. **CPE**: `GET /rest/json/cpes/2.0?keywordSearch=<nombre>`. Se elige el par `fabricante:producto` más parecido. Para aceptarlo, casi todas las palabras del producto deben aparecer en el nombre y la similitud debe superar 0,60. Se guarda `confianza_cpe` (ALTA/MEDIA/MANUAL) y los candidatos alternativos.
3. **CVE**: `GET /rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:<fabricante>:<producto>:<versión>`.
4. **Comparación local de versiones** con `packaging.version.Version` (nunca como texto: `"10.0" < "9.0"` como cadena, pero 10.0 > 9.0 como versión). Se usan los rangos `versionStart/EndIncluding/Excluding` de `configurations` (análisis NVD) y, si un CVE no está analizado, los datos del CNA (`affected`).
5. **CVSS**: v3.1 → v3.0 → v2.0 (se prefiere la métrica *Primary* de la NVD).

### Estados

- `estado_identificacion`: `IDENTIFICADO`, `SIN_COINCIDENCIA_CPE`, `ERROR_NVD`.
- `estado_version` (por CVE) y `estado_programa`:
  - `AFECTADO`: la versión instalada está dentro de un rango afectado.
  - `NO_AFECTADO`: hay rangos y la versión no está en ninguno (o la NVD no devuelve CVE analizados).
  - `INDETERMINADO`: versión no interpretable, rango sin límites o sin datos de versión.

En `vulnerabilidades.json`, `versiones_afectadas` usa: `desde` (= `versionStartExcluding`), `desde_incluido`, `hasta_excluido`, `hasta_incluido`, `version_exacta` y `origen` (`NVD` o `CNA`).

### Corregir un CPE a mano

Si un programa se identifica mal o no se encuentra, crea `cpe_manual.json` (ver `cpe_manual.json.ejemplo`) con `{"Nombre limpio": "fabricante:producto"}`. Esos programas se marcan con confianza `MANUAL`.

## 6. Límites e interpretación (importante)

- **Una coincidencia de nombre no confirma la identidad del producto.** Revisa `confianza_cpe` y `candidatos_cpe`.
- **La ausencia de resultados no demuestra seguridad.** Muchos programas no están en el diccionario CPE (`SIN_COINCIDENCIA_CPE`), y la búsqueda por CPE solo encuentra CVE **ya analizados por la NVD**: los CVE en estado *Awaiting Analysis* o *Deferred* sin `configurations` no aparecen en `virtualMatchString` (p. ej. CVE-2024-46461 de VLC, incluido en los fixtures).
- **CVSS es gravedad técnica, no riesgo real**: el riesgo depende de la exposición, de si el componente se usa, etc.
- No se han instalado versiones vulnerables para probar: los tests usan respuestas reales guardadas.
- Límite de la NVD: 5 peticiones/30 s sin clave, 50/30 s con clave. Ante HTTP 403/429/5xx el módulo reintenta 3 veces (esperas de 10, 20 y 40 s).

## 7. Tests

```powershell
python -m pytest -v test_identificacion.py
# o, sin pytest:
python -m unittest -v test_identificacion
```

Casos cubiertos (con CVE reales de `fixtures/`):

- **(a) Versión afectada**: WinRAR 6.00 → 7 CVE reales `AFECTADO` (CVE-2023-38831, CVE-2023-40477, CVE-2025-8088…); los mismos CVE con 7.13.0 → `NO_AFECTADO`. VLC 3.0.20 frente a CVE-2024-46461 (datos CNA) → `AFECTADO`; 3.0.24 → `NO_AFECTADO`.
- **(b) Sin coincidencia CPE**: "Configurador FNMT" (la NVD devuelve 0 resultados) y un nombre no relacionado frente a los CPE de VLC.
- **(c) Versión indeterminada**: versión no interpretable, CVE sin rangos para el producto y rango sin límites.
- **(d) Error de comunicación**: error de red (3 reintentos con backoff → `ERROR_NVD`, sin romper el análisis), reintento tras HTTP 429, HTTP 400 sin reintento, cabecera `apiKey`.
- Generación completa de `vulnerabilidades.json` en carpeta temporal.
