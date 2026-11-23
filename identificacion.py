#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecureWatch - Semana 10: identificación de software vulnerable (API NVD 2.0).

Flujo completo:
1. Normalizar el inventario de software.json (descartar entradas sin versión,
   limpiar nombres y eliminar duplicados).
2. Buscar el CPE oficial de cada programa en el diccionario CPE de la NVD
   (GET /rest/json/cpes/2.0?keywordSearch=...).
3. Consultar los CVE asociados a ese producto
   (GET /rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:<fabricante>:<producto>:<versión>).
4. Comparar LOCALMENTE la versión instalada con los rangos afectados de cada
   CVE usando packaging.version (nunca como cadenas de texto).
5. Extraer CVSS (v3.1 -> v3.0 -> v2.0), descripción y referencias.
6. Generar vulnerabilidades.json.

Reglas que respeta el módulo (enunciado de la Semana 10):
- Una coincidencia de nombre NO confirma la identidad del producto: por eso se
  guarda la confianza de la coincidencia y los candidatos alternativos, y se
  admite un archivo cpe_manual.json para fijar a mano el CPE correcto.
- Si no se puede determinar si la versión está afectada -> INDETERMINADO.
- La ausencia de resultados NO demuestra que el programa sea seguro.
- CVSS mide la gravedad técnica de la vulnerabilidad, no el riesgo real.

Control de tasa de la API NVD:
- Sin API key: 5 peticiones / 30 s  -> pausa de 6 s entre peticiones.
- Con API key (variable de entorno NVD_API_KEY): 50 peticiones / 30 s
  -> pausa de 0,6 s. La clave se envía en la cabecera "apiKey".
- HTTP 429/403/503: hasta 3 reintentos con espera exponencial.

"This product uses the NVD API but is not endorsed or certified by the NVD."

Uso independiente:
    python identificacion.py                 analiza software.json de esta carpeta
    python identificacion.py --max 5         analiza solo los 5 primeros programas
"""

import argparse
import difflib
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

try:
    from packaging.version import InvalidVersion, Version
except ImportError:  # pragma: no cover - solo si falta la dependencia
    print("Error: falta el paquete 'packaging'. Instálalo con: python -m pip install packaging")
    raise

CARPETA_PROGRAMA = Path(__file__).resolve().parent

URL_CPES = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
URL_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0"

ARCHIVO_SALIDA = "vulnerabilidades.json"
ARCHIVO_CACHE = "nvd_cache.json"
ARCHIVO_CPE_MANUAL = "cpe_manual.json"

PAUSA_SIN_CLAVE = 6.0       # 5 peticiones cada 30 s
PAUSA_CON_CLAVE = 0.6       # 50 peticiones cada 30 s
MAX_REINTENTOS = 3
ESPERA_BASE_REINTENTO = 10  # segundos (10, 20, 40)
TIEMPO_ESPERA_NVD = 30      # timeout de cada petición HTTP
RESULTADOS_CPE = 20         # candidatos CPE pedidos por búsqueda
RESULTADOS_CVE = 2000       # máximo permitido por la API en cves/2.0
CADUCIDAD_CACHE_HORAS = 24
MAX_REFERENCIAS = 5
MAX_CVE_CONSOLA = 10        # CVE afectados mostrados por programa en consola

# Puntuación mínima de similitud para aceptar un CPE candidato.
UMBRAL_COINCIDENCIA = 0.60
UMBRAL_CONFIANZA_ALTA = 0.85
# Fracción mínima de palabras del producto CPE presentes en el nombre.
COBERTURA_MINIMA_PRODUCTO = 0.75

AVISO_NVD = "This product uses the NVD API but is not endorsed or certified by the NVD."

# Estados de identificación del producto
IDENTIFICADO = "IDENTIFICADO"
SIN_COINCIDENCIA_CPE = "SIN_COINCIDENCIA_CPE"
ERROR_NVD = "ERROR_NVD"

# Estados de la versión frente a un CVE
AFECTADO = "AFECTADO"
NO_AFECTADO = "NO_AFECTADO"
INDETERMINADO = "INDETERMINADO"

# SecureWatch analiza equipos Windows: las entradas CPE de otra plataforma
# (target_sw = macos, android, iphone_os...) no se aplican a este equipo.
PLATAFORMAS_COMPATIBLES = {"*", "-", "", "windows", "universal"}

# Palabras que no aportan nada a la búsqueda del CPE.
TOKENS_ARQUITECTURA = {"64-bit", "32-bit", "x64", "x86", "amd64", "arm64", "64bit", "32bit", "win64", "win32"}


class ErrorNVD(Exception):
    """Error de comunicación con la API NVD (red, timeout o HTTP no válido)."""


# ---------------------------------------------------------------------------
# Utilidades JSON (mismo criterio que el resto del proyecto)
# ---------------------------------------------------------------------------

def leer_json_ruta(ruta: Path) -> Optional[Any]:
    """Lee un JSON admitiendo BOM (PowerShell lo añade a veces). None si falla."""
    try:
        with open(ruta, "r", encoding="utf-8-sig") as archivo:
            return json.load(archivo)
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as error:
        print(f"Aviso: no se pudo leer {ruta.name}: {error}")
        return None


def guardar_json_atomico(ruta: Path, datos: Any) -> None:
    """Escribe el JSON en un temporal y lo sustituye con os.replace (atómico)."""
    temporal = ruta.with_suffix(ruta.suffix + ".tmp")
    with open(temporal, "w", encoding="utf-8") as archivo:
        json.dump(datos, archivo, ensure_ascii=False, indent=4)
        archivo.write("\n")
    os.replace(temporal, ruta)


# ---------------------------------------------------------------------------
# 1. Normalización del inventario
# ---------------------------------------------------------------------------

def limpiar_version(version: Any) -> Optional[str]:
    """Devuelve la versión limpia o None si no hay versión utilizable.

    Ejemplos: "7.2.0 (48358)" -> "7.2.0"; "v1.2" -> "1.2"; "" -> None.
    Si el texto no empieza por un número se devuelve tal cual (recortado):
    más adelante packaging no podrá interpretarlo y el CVE quedará
    INDETERMINADO, que es lo correcto.
    """
    if version is None:
        return None
    texto = str(version).strip()
    if not texto or texto.lower() in ("null", "none", "n/a", "-", "desconocida", "desconocido"):
        return None
    coincidencia = re.match(r"^[vV]?(\d+(?:\.\d+)*)", texto)
    if coincidencia:
        return coincidencia.group(1)
    return texto


def limpiar_nombre(nombre: str, version: Optional[str] = None) -> str:
    """Limpia el nombre comercial para buscarlo en el diccionario CPE.

    - Quita el contenido entre paréntesis: "(64-bit)", "(User)", "(x64)".
    - Quita sufijos de idioma: " - en-us", " - es-es".
    - Quita "versión X" / "version X" y números de versión incrustados.
    - Quita tokens de arquitectura y un número final si coincide con el
      inicio de la versión instalada ("Spyder 6" con versión 6.1.7).
    """
    texto = re.sub(r"\([^)]*\)", " ", nombre)
    texto = re.sub(r"\s+-\s+[a-z]{2}-[a-z]{2}\b", " ", texto, flags=re.IGNORECASE)
    texto = re.sub(r"\bversi[oó]n\s*\S+", " ", texto, flags=re.IGNORECASE)
    texto = re.sub(r"\b\d+(?:\.\d+)+\b", " ", texto)  # 7.13, 19.2.5 ...

    tokens = [t for t in texto.split() if t.lower() not in TOKENS_ARQUITECTURA]

    if version and tokens and tokens[-1].isdigit():
        primer_bloque = version.split(".")[0]
        if tokens[-1] == primer_bloque:
            tokens.pop()

    limpio = " ".join(tokens).strip(" -_")
    return limpio or nombre.strip()


def normalizar_inventario(software: Any) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Convierte software.json en una lista de programas analizables.

    Devuelve (programas, contadores). Cada programa:
    {"nombre_original", "programa", "version_original", "version"}.
    """
    contadores = {"total_entradas": 0, "sin_version": 0, "duplicados": 0}
    if isinstance(software, dict):
        software = [software]
    if not isinstance(software, list):
        return [], contadores

    programas: List[Dict[str, Any]] = []
    vistos = set()

    for entrada in software:
        if not isinstance(entrada, dict):
            continue
        nombre = entrada.get("Name", entrada.get("nombre", entrada.get("DisplayName")))
        if not isinstance(nombre, str) or not nombre.strip():
            continue
        contadores["total_entradas"] += 1

        version_original = entrada.get("Version", entrada.get("version", entrada.get("DisplayVersion")))
        version = limpiar_version(version_original)
        if version is None:
            contadores["sin_version"] += 1
            continue

        programa = limpiar_nombre(nombre.strip(), version)
        clave = (programa.lower(), version)
        if clave in vistos:
            contadores["duplicados"] += 1
            continue
        vistos.add(clave)

        programas.append(
            {
                "nombre_original": nombre.strip(),
                "programa": programa,
                "version_original": str(version_original).strip(),
                "version": version,
            }
        )

    return programas, contadores


# ---------------------------------------------------------------------------
# Cliente de la API NVD con control de tasa, reintentos y caché
# ---------------------------------------------------------------------------

class ClienteNVD:
    """Cliente mínimo de la API NVD 2.0.

    sesion y dormir se pueden sustituir en los tests para no llamar a la red.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        sesion: Optional[Any] = None,
        dormir: Callable[[float], None] = time.sleep,
        ruta_cache: Optional[Path] = None,
        usar_cache: bool = True,
    ) -> None:
        self.api_key = api_key.strip() if isinstance(api_key, str) and api_key.strip() else None
        self.sesion = sesion if sesion is not None else requests.Session()
        self.dormir = dormir
        self.pausa = PAUSA_CON_CLAVE if self.api_key else PAUSA_SIN_CLAVE
        self._ultima_peticion: Optional[float] = None
        self.peticiones_realizadas = 0
        self.ruta_cache = ruta_cache
        self.usar_cache = usar_cache and ruta_cache is not None
        self._cache: Dict[str, Any] = {}
        if self.usar_cache:
            datos = leer_json_ruta(ruta_cache)
            self._cache = datos if isinstance(datos, dict) else {}

    # -- caché ---------------------------------------------------------------

    @staticmethod
    def _clave_cache(url: str, parametros: Dict[str, Any]) -> str:
        return url + "?" + "&".join(f"{k}={parametros[k]}" for k in sorted(parametros))

    def _leer_cache(self, clave: str) -> Optional[Dict[str, Any]]:
        if not self.usar_cache:
            return None
        entrada = self._cache.get(clave)
        if not isinstance(entrada, dict):
            return None
        try:
            guardado = datetime.fromisoformat(entrada["guardado_en"])
        except (KeyError, ValueError, TypeError):
            return None
        horas = (datetime.now().astimezone() - guardado).total_seconds() / 3600
        if horas > CADUCIDAD_CACHE_HORAS:
            return None
        return entrada.get("datos")

    def _escribir_cache(self, clave: str, datos: Dict[str, Any]) -> None:
        if not self.usar_cache:
            return
        self._cache[clave] = {
            "guardado_en": datetime.now().astimezone().isoformat(timespec="seconds"),
            "datos": datos,
        }

    def guardar_cache(self) -> None:
        """Persiste la caché de respuestas en disco (escritura atómica)."""
        if self.usar_cache and self.ruta_cache is not None:
            try:
                guardar_json_atomico(self.ruta_cache, self._cache)
            except OSError as error:
                print(f"Aviso: no se pudo guardar la caché NVD: {error}")

    # -- peticiones ----------------------------------------------------------

    def _respetar_tasa(self) -> None:
        """Espera lo necesario para no superar el límite de la API."""
        if self._ultima_peticion is not None:
            transcurrido = time.monotonic() - self._ultima_peticion
            if transcurrido < self.pausa:
                self.dormir(self.pausa - transcurrido)
        self._ultima_peticion = time.monotonic()

    def obtener(self, url: str, parametros: Dict[str, Any]) -> Dict[str, Any]:
        """GET con caché, control de tasa y reintentos. Lanza ErrorNVD si falla."""
        clave = self._clave_cache(url, parametros)
        en_cache = self._leer_cache(clave)
        if en_cache is not None:
            return en_cache

        cabeceras = {"User-Agent": "SecureWatch/10 (proyecto academico)"}
        if self.api_key:
            cabeceras["apiKey"] = self.api_key

        ultimo_error = "sin respuesta"
        for intento in range(MAX_REINTENTOS + 1):
            self._respetar_tasa()
            try:
                respuesta = self.sesion.get(url, params=parametros, headers=cabeceras, timeout=TIEMPO_ESPERA_NVD)
                self.peticiones_realizadas += 1
            except requests.exceptions.RequestException as error:
                ultimo_error = f"error de red: {error}"
            else:
                codigo = respuesta.status_code
                if codigo == 200:
                    try:
                        datos = respuesta.json()
                    except ValueError as error:
                        raise ErrorNVD(f"la NVD devolvió una respuesta que no es JSON ({error})") from error
                    self._escribir_cache(clave, datos)
                    return datos
                if codigo == 404 and "cpeName" in parametros:
                    raise ErrorNVD("CPE no encontrado en el diccionario (HTTP 404)")
                if codigo not in (403, 429, 500, 502, 503, 504):
                    mensaje = respuesta.headers.get("message", "") if hasattr(respuesta, "headers") else ""
                    raise ErrorNVD(f"HTTP {codigo} {mensaje}".strip())
                ultimo_error = f"HTTP {codigo}"

            if intento < MAX_REINTENTOS:
                espera = ESPERA_BASE_REINTENTO * (2 ** intento)
                print(f"  NVD: {ultimo_error}. Reintento {intento + 1}/{MAX_REINTENTOS} en {espera} s ...")
                self.dormir(espera)

        raise ErrorNVD(f"no se pudo consultar la NVD tras {MAX_REINTENTOS} reintentos ({ultimo_error})")

    def buscar_cpe(self, palabras: str) -> List[Dict[str, Any]]:
        """Busca productos en el diccionario CPE por palabras clave."""
        datos = self.obtener(URL_CPES, {"keywordSearch": palabras, "resultsPerPage": RESULTADOS_CPE})
        productos = datos.get("products", [])
        return productos if isinstance(productos, list) else []

    def buscar_cves(self, cadena_cpe: str) -> List[Dict[str, Any]]:
        """Devuelve todos los CVE cuya configuración coincide con la cadena CPE.

        Se usa virtualMatchString porque admite rangos de versiones y no
        exige que la versión exacta exista en el diccionario CPE. Pagina
        automáticamente si hay más de RESULTADOS_CVE resultados.
        """
        vulnerabilidades: List[Dict[str, Any]] = []
        inicio = 0
        while True:
            datos = self.obtener(
                URL_CVES,
                {"virtualMatchString": cadena_cpe, "resultsPerPage": RESULTADOS_CVE, "startIndex": inicio},
            )
            pagina = datos.get("vulnerabilities", [])
            if not isinstance(pagina, list):
                break
            vulnerabilidades.extend(pagina)
            total = int(datos.get("totalResults", 0) or 0)
            inicio += len(pagina)
            if not pagina or inicio >= total:
                break
        return vulnerabilidades


# ---------------------------------------------------------------------------
# 2. Identificación del CPE
# ---------------------------------------------------------------------------

def partes_cpe(cpe: str) -> Dict[str, str]:
    """Separa una cadena CPE 2.3 en sus campos principales."""
    campos = cpe.split(":")
    campos += ["*"] * (13 - len(campos))
    return {
        "tipo": campos[2],
        "fabricante": campos[3],
        "producto": campos[4],
        "version": campos[5],
        "plataforma": campos[10],  # target_sw: windows, macos, android...
    }


def _normalizar_texto(texto: str) -> str:
    texto = texto.lower().replace("_", " ").replace("-", " ")
    texto = re.sub(r"[^a-z0-9+ ]", " ", texto)
    return " ".join(texto.split())


def puntuar_candidato(programa: str, fabricante: str, producto: str, titulo: str) -> float:
    """Similitud (0-1+) entre el nombre del inventario y un CPE candidato.

    Combina la similitud de secuencia con el solapamiento de palabras y da
    una bonificación si el fabricante aparece en el nombre del programa.
    Es solo un indicio: una coincidencia de nombre no confirma la identidad.
    """
    nombre = _normalizar_texto(programa)
    prod = _normalizar_texto(producto)
    fab = _normalizar_texto(fabricante)
    titulo_n = _normalizar_texto(re.sub(r"\b\d+(?:\.\d+)*\S*\b", " ", titulo or ""))

    # El nombre del programa sin el fabricante ("vlc media player").
    nombre_sin_fab = " ".join(t for t in nombre.split() if t not in fab.split()) or nombre

    sim = max(
        difflib.SequenceMatcher(None, nombre, prod).ratio(),
        difflib.SequenceMatcher(None, nombre_sin_fab, prod).ratio(),
        difflib.SequenceMatcher(None, nombre, titulo_n).ratio() if titulo_n else 0.0,
        difflib.SequenceMatcher(None, nombre, f"{fab} {prod}").ratio(),
    )
    tokens_nombre = set(nombre_sin_fab.split())
    tokens_prod = set(prod.split())
    if tokens_nombre and tokens_prod:
        solape = len(tokens_nombre & tokens_prod) / len(tokens_nombre | tokens_prod)
        sim = max(sim, solape)

    # Filtro de identidad: casi todas las palabras del producto CPE deben
    # aparecer en el nombre del programa. Evita aceptar, por ejemplo,
    # "hp:color_laserjet_2500_toolbox" para "HP Color LaserJet Pro M453-4".
    if tokens_prod:
        nombre_junto = nombre.replace(" ", "")
        presentes = sum(1 for t in tokens_prod if t in nombre.split() or t in nombre_junto)
        if presentes / len(tokens_prod) < COBERTURA_MINIMA_PRODUCTO:
            return 0.0

    if fab and any(t == fab or t in fab.split() for t in nombre.split()):
        sim += 0.10
    return round(min(sim, 1.0), 3)


def elegir_cpe(programa: str, productos: List[Dict[str, Any]]) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    """Elige el par fabricante:producto más probable entre los resultados CPE.

    Devuelve (mejor, candidatos). mejor es None si nadie supera el umbral.
    """
    agrupados: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for item in productos:
        cpe = item.get("cpe", {}) if isinstance(item, dict) else {}
        nombre_cpe = cpe.get("cpeName")
        if not isinstance(nombre_cpe, str) or not nombre_cpe.startswith("cpe:2.3:"):
            continue
        partes = partes_cpe(nombre_cpe)
        if partes["tipo"] != "a":  # solo aplicaciones (no SO ni hardware)
            continue
        titulo = ""
        for t in cpe.get("titles", []) or []:
            if t.get("lang") == "en":
                titulo = t.get("title", "")
                break
        puntuacion = puntuar_candidato(programa, partes["fabricante"], partes["producto"], titulo)
        if cpe.get("deprecated"):
            puntuacion -= 0.05
        clave = (partes["fabricante"], partes["producto"])
        if clave not in agrupados or puntuacion > agrupados[clave]["puntuacion"]:
            agrupados[clave] = {
                "fabricante": partes["fabricante"],
                "producto": partes["producto"],
                "titulo": re.sub(r"\s+\d+(?:\.\d+)*\S*$", "", titulo).strip(),
                "puntuacion": round(puntuacion, 3),
            }

    candidatos = sorted(agrupados.values(), key=lambda c: c["puntuacion"], reverse=True)
    if candidatos and candidatos[0]["puntuacion"] >= UMBRAL_COINCIDENCIA:
        return candidatos[0], candidatos[:5]
    return None, candidatos[:5]


def identificar_cpe(
    cliente: ClienteNVD, programa: str, manual: Optional[Dict[str, str]] = None
) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]], str]:
    """Busca el CPE de un programa. Devuelve (mejor, candidatos, confianza).

    Orden: 1) cpe_manual.json; 2) búsqueda por el nombre limpio completo;
    3) si no hay resultados y el nombre tiene más de dos palabras, una
    segunda búsqueda con las dos primeras. Lanza ErrorNVD si la API falla.
    """
    if manual:
        valor = manual.get(programa) or manual.get(programa.lower())
        if isinstance(valor, str) and ":" in valor:
            fabricante, producto = valor.split(":", 1)
            mejor = {"fabricante": fabricante, "producto": producto, "titulo": programa, "puntuacion": 1.0}
            return mejor, [mejor], "MANUAL"

    productos = cliente.buscar_cpe(programa)
    palabras = programa.split()
    if not productos and len(palabras) > 2:
        productos = cliente.buscar_cpe(" ".join(palabras[:2]))

    mejor, candidatos = elegir_cpe(programa, productos)
    if mejor is None:
        return None, candidatos, "NINGUNA"
    confianza = "ALTA" if mejor["puntuacion"] >= UMBRAL_CONFIANZA_ALTA else "MEDIA"
    return mejor, candidatos, confianza


# ---------------------------------------------------------------------------
# 3-4. Análisis de cada CVE y comparación de versiones
# ---------------------------------------------------------------------------

def parsear_version(texto: Any) -> Optional[Version]:
    """Version de packaging o None si no es interpretable."""
    if texto is None:
        return None
    try:
        return Version(str(texto).strip())
    except InvalidVersion:
        return None


def version_en_rango(instalada: Version, rango: Dict[str, Optional[str]]) -> Optional[bool]:
    """True/False si la versión está o no en el rango; None si no se puede saber.

    Las claves del rango siguen la estructura de vulnerabilidades.json:
    version_exacta, desde (excluido), desde_incluido, hasta_excluido,
    hasta_incluido.
    """
    if rango.get("version_exacta") is not None:
        exacta = parsear_version(rango["version_exacta"])
        return None if exacta is None else instalada == exacta

    limites = {
        "desde": lambda v, l: v > l,
        "desde_incluido": lambda v, l: v >= l,
        "hasta_excluido": lambda v, l: v < l,
        "hasta_incluido": lambda v, l: v <= l,
    }
    hay_limite = False
    for clave, comparar in limites.items():
        valor = rango.get(clave)
        if valor is None:
            continue
        hay_limite = True
        limite = parsear_version(valor)
        if limite is None:
            return None
        if not comparar(instalada, limite):
            return False
    # Un rango sin ningún límite equivale a "todas las versiones": la NVD no
    # concreta qué versiones están afectadas -> no se puede determinar.
    return True if hay_limite else None


def _rango_vacio() -> Dict[str, Optional[str]]:
    return {"desde": None, "desde_incluido": None, "hasta_excluido": None, "hasta_incluido": None, "version_exacta": None}


def extraer_rangos_configuracion(
    cve: Dict[str, Any], fabricante: str, producto: str, descartadas: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """Rangos afectados según el análisis de la NVD (campo configurations).

    Solo se tienen en cuenta las entradas vulnerable=true del mismo
    fabricante y producto (se ignoran las de "se ejecuta en Windows", etc.)
    y de una plataforma compatible con Windows (target_sw). Las plataformas
    descartadas se añaden a la lista "descartadas" si se proporciona.
    """
    rangos: List[Dict[str, Any]] = []
    for configuracion in cve.get("configurations", []) or []:
        for nodo in configuracion.get("nodes", []) or []:
            for coincidencia in nodo.get("cpeMatch", []) or []:
                if not coincidencia.get("vulnerable"):
                    continue
                criterio = coincidencia.get("criteria", "")
                partes = partes_cpe(criterio)
                if partes["fabricante"] != fabricante or partes["producto"] != producto:
                    continue
                if partes["plataforma"].lower() not in PLATAFORMAS_COMPATIBLES:
                    if descartadas is not None and partes["plataforma"] not in descartadas:
                        descartadas.append(partes["plataforma"])
                    continue
                rango = _rango_vacio()
                rango["desde"] = coincidencia.get("versionStartExcluding")
                rango["desde_incluido"] = coincidencia.get("versionStartIncluding")
                rango["hasta_excluido"] = coincidencia.get("versionEndExcluding")
                rango["hasta_incluido"] = coincidencia.get("versionEndIncluding")
                if all(rango[k] is None for k in ("desde", "desde_incluido", "hasta_excluido", "hasta_incluido")):
                    if partes["version"] not in ("*", "-", ""):
                        rango["version_exacta"] = partes["version"]
                rango["criterio_cpe"] = criterio
                rango["origen"] = "NVD"
                rangos.append(rango)
    return rangos


def extraer_rangos_cna(cve: Dict[str, Any], fabricante: str, producto: str) -> List[Dict[str, Any]]:
    """Rangos declarados por el CNA (campo affected), para CVE aún sin analizar.

    Muchos CVE recientes están en estado "Deferred" o "Awaiting Analysis" y
    no tienen configurations, pero sí datos del CNA con el formato CVE 5.x.
    """
    rangos: List[Dict[str, Any]] = []
    for bloque in cve.get("affected", []) or []:
        for dato in bloque.get("affectedData", []) or []:
            vendor = str(dato.get("vendor", "")).lower()
            product = str(dato.get("product", "")).lower()
            cpes = [partes_cpe(c) for c in dato.get("cpes", []) or [] if isinstance(c, str)]
            coincide = (vendor == fabricante and product == producto) or any(
                c["fabricante"] == fabricante and c["producto"] == producto for c in cpes
            )
            if not coincide:
                continue
            for v in dato.get("versions", []) or []:
                if v.get("status") != "affected":
                    continue
                rango = _rango_vacio()
                base = v.get("version")
                if v.get("versionType") == "git" or base in (None, "n/a", "unspecified"):
                    rango["version_exacta"] = None  # no comparable -> INDETERMINADO
                    rango["sin_datos"] = True
                elif v.get("lessThan") or v.get("lessThanOrEqual"):
                    if base not in ("0", "*"):
                        rango["desde_incluido"] = base
                    rango["hasta_excluido"] = v.get("lessThan")
                    rango["hasta_incluido"] = v.get("lessThanOrEqual")
                    if rango["hasta_excluido"] == "*":
                        rango["hasta_excluido"] = None
                else:
                    rango["version_exacta"] = base
                rango["origen"] = "CNA"
                rangos.append(rango)
    return rangos


def evaluar_version(version_instalada: str, rangos: List[Dict[str, Any]]) -> str:
    """AFECTADO / NO_AFECTADO / INDETERMINADO para una versión y sus rangos."""
    if not rangos:
        return INDETERMINADO
    instalada = parsear_version(version_instalada)
    if instalada is None:
        return INDETERMINADO

    hay_indeterminado = False
    for rango in rangos:
        resultado = None if rango.get("sin_datos") else version_en_rango(instalada, rango)
        if resultado is True:
            return AFECTADO
        if resultado is None:
            hay_indeterminado = True
    return INDETERMINADO if hay_indeterminado else NO_AFECTADO


def extraer_cvss(metricas: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """CVSS v3.1 -> v3.0 -> v2.0 (y v4.0 solo si no hay otra).

    Dentro de cada versión se prefiere la métrica "Primary" (la de la NVD)
    frente a la "Secondary" (la del CNA).
    """
    orden = (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0"), ("cvssMetricV40", "4.0"))
    for clave, version in orden:
        lista = metricas.get(clave) or []
        if not lista:
            continue
        lista = sorted(lista, key=lambda m: 0 if m.get("type") == "Primary" else 1)
        metrica = lista[0]
        datos = metrica.get("cvssData", {})
        return {
            "version": version,
            "score": datos.get("baseScore"),
            "severidad": datos.get("baseSeverity") or metrica.get("baseSeverity"),
            "vector": datos.get("vectorString"),
            "fuente": metrica.get("source"),
        }
    return None


def analizar_cve(item: Dict[str, Any], fabricante: str, producto: str, version_instalada: str) -> Dict[str, Any]:
    """Construye la entrada de un CVE para vulnerabilidades.json."""
    cve = item.get("cve", item)
    descripcion = ""
    for d in cve.get("descriptions", []) or []:
        if d.get("lang") == "en":
            descripcion = d.get("value", "")
            break

    descartadas: List[str] = []
    rangos = extraer_rangos_configuracion(cve, fabricante, producto, descartadas)
    if not rangos and not descartadas:
        rangos = extraer_rangos_cna(cve, fabricante, producto)

    if rangos:
        estado = evaluar_version(version_instalada, rangos)
        nota = None
    elif descartadas:
        # La NVD solo lista este producto en otras plataformas (p. ej. Acrobat
        # dentro de Edge o la versión de macOS): no aplica a este equipo.
        estado = NO_AFECTADO
        nota = f"Solo afecta a otras plataformas: {', '.join(descartadas)}."
    else:
        estado = INDETERMINADO
        nota = "La NVD no indica qué versiones están afectadas."

    referencias = []
    for ref in cve.get("references", []) or []:
        url = ref.get("url")
        if url and url not in referencias:
            referencias.append(url)
        if len(referencias) >= MAX_REFERENCIAS:
            break

    versiones_afectadas = [
        {k: r.get(k) for k in ("desde", "desde_incluido", "hasta_excluido", "hasta_incluido", "version_exacta", "origen")}
        for r in rangos
    ]

    return {
        "cve_id": cve.get("id"),
        "descripcion": descripcion,
        "producto_afectado": producto,
        "estado_nvd": cve.get("vulnStatus"),
        "publicado": cve.get("published"),
        "versiones_afectadas": versiones_afectadas,
        "estado_version": estado,
        "nota": nota,
        "cvss": extraer_cvss(cve.get("metrics", {}) or {}),
        "referencias": referencias,
    }


def estado_programa(vulnerabilidades: List[Dict[str, Any]]) -> str:
    """Estado global del programa a partir de sus CVE."""
    estados = {v["estado_version"] for v in vulnerabilidades}
    if AFECTADO in estados:
        return AFECTADO
    if INDETERMINADO in estados:
        return INDETERMINADO
    return NO_AFECTADO


def analizar_programa(cliente: ClienteNVD, programa: Dict[str, Any], manual: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Identifica el CPE de un programa y evalúa sus CVE. Nunca lanza ErrorNVD."""
    resultado: Dict[str, Any] = {
        "programa": programa["programa"],
        "nombre_original": programa["nombre_original"],
        "fabricante_detectado": None,
        "version_instalada": programa["version"],
        "cpe_identificado": None,
        "confianza_cpe": "NINGUNA",
        "candidatos_cpe": [],
        "estado_identificacion": SIN_COINCIDENCIA_CPE,
        "estado_programa": None,
        "vulnerabilidades": [],
        "nota": None,
    }

    try:
        mejor, candidatos, confianza = identificar_cpe(cliente, programa["programa"], manual)
        resultado["candidatos_cpe"] = [f"{c['fabricante']}:{c['producto']} ({c['puntuacion']})" for c in candidatos]
        if mejor is None:
            resultado["nota"] = (
                "No se ha encontrado un CPE fiable en la NVD. Esto NO demuestra que el "
                "programa sea seguro: puede faltar en el diccionario o usar otro nombre."
            )
            return resultado

        fabricante, producto = mejor["fabricante"], mejor["producto"]
        resultado["fabricante_detectado"] = fabricante
        resultado["cpe_identificado"] = f"cpe:2.3:a:{fabricante}:{producto}:*:*:*:*:*:*:*:*"
        resultado["confianza_cpe"] = confianza
        resultado["estado_identificacion"] = IDENTIFICADO

        # La versión solo se incluye en la consulta si no tiene caracteres que
        # rompan la cadena CPE; la verificación definitiva siempre es local.
        version = programa["version"]
        cadena = f"cpe:2.3:a:{fabricante}:{producto}"
        if re.fullmatch(r"[0-9A-Za-z._\-]+", version):
            cadena += f":{version}"
        items = cliente.buscar_cves(cadena)
    except ErrorNVD as error:
        # Con error de red no se puede afirmar nada: ni identificado ni seguro.
        resultado["estado_identificacion"] = ERROR_NVD
        resultado["estado_programa"] = INDETERMINADO
        resultado["vulnerabilidades"] = []
        resultado["nota"] = f"Error de comunicación con la NVD: {error}. Resultado no concluyente."
        return resultado

    resultado["vulnerabilidades"] = [analizar_cve(i, fabricante, producto, programa["version"]) for i in items]
    resultado["vulnerabilidades"].sort(
        key=lambda v: ({AFECTADO: 0, INDETERMINADO: 1, NO_AFECTADO: 2}[v["estado_version"]], -((v["cvss"] or {}).get("score") or 0))
    )
    resultado["estado_programa"] = estado_programa(resultado["vulnerabilidades"])
    if not items:
        resultado["nota"] = (
            "La NVD no devuelve CVE analizados para esta versión. La ausencia de "
            "resultados no demuestra que sea segura (puede haber CVE pendientes de análisis)."
        )
    if confianza == "MEDIA":
        aviso = "Coincidencia de CPE de confianza media: verificar manualmente (cpe_manual.json)."
        resultado["nota"] = f"{resultado['nota']} {aviso}" if resultado["nota"] else aviso
    return resultado


# ---------------------------------------------------------------------------
# 5. Informe final
# ---------------------------------------------------------------------------

def construir_resumen(total_entradas: int, programas: List[Dict[str, Any]], resultados: List[Dict[str, Any]]) -> Dict[str, int]:
    identificados = [r for r in resultados if r["estado_identificacion"] == IDENTIFICADO]
    todas = [v for r in identificados for v in r["vulnerabilidades"]]
    return {
        "total_programas_analizados": total_entradas,
        "programas_con_version": len(programas),
        "programas_identificados_cpe": len(identificados),
        "sin_coincidencia_cpe": sum(1 for r in resultados if r["estado_identificacion"] == SIN_COINCIDENCIA_CPE),
        "errores_consulta_nvd": sum(1 for r in resultados if r["estado_identificacion"] == ERROR_NVD),
        "programas_afectados": sum(1 for r in identificados if r["estado_programa"] == AFECTADO),
        "programas_no_afectados": sum(1 for r in identificados if r["estado_programa"] == NO_AFECTADO),
        "programas_indeterminados": sum(1 for r in identificados if r["estado_programa"] == INDETERMINADO),
        "total_cve_encontrados": len(todas),
        "cve_afectados": sum(1 for v in todas if v["estado_version"] == AFECTADO),
        "cve_indeterminados": sum(1 for v in todas if v["estado_version"] == INDETERMINADO),
    }


def cargar_cpe_manual(carpeta: Path) -> Dict[str, str]:
    """Lee cpe_manual.json: {"Nombre limpio": "fabricante:producto"} (opcional)."""
    datos = leer_json_ruta(carpeta / ARCHIVO_CPE_MANUAL)
    if not isinstance(datos, dict):
        return {}
    manual = {}
    for k, v in datos.items():
        if isinstance(k, str) and isinstance(v, str):
            manual[k] = v
            manual[k.lower()] = v
    return manual


def analizar_vulnerabilidades(
    carpeta: Optional[Path] = None,
    cliente: Optional[ClienteNVD] = None,
    max_programas: Optional[int] = None,
    guardar: bool = True,
) -> Dict[str, Any]:
    """Punto de entrada: lee equipo.json + software.json y genera vulnerabilidades.json.

    Devuelve el informe generado (también cuando no se guarda en disco).
    """
    carpeta = Path(carpeta) if carpeta else CARPETA_PROGRAMA
    equipo = leer_json_ruta(carpeta / "equipo.json")
    equipo = equipo if isinstance(equipo, dict) else {}
    software = leer_json_ruta(carpeta / "software.json")
    if software is None:
        print("Aviso: no se encontró software.json o no es válido; no hay inventario que analizar.")

    programas, contadores = normalizar_inventario(software)
    if max_programas is not None:
        programas = programas[:max_programas]

    if cliente is None:
        cliente = ClienteNVD(api_key=os.environ.get("NVD_API_KEY"), ruta_cache=carpeta / ARCHIVO_CACHE)

    modo = "con API key" if cliente.api_key else "sin API key (6 s entre peticiones)"
    print(f"Identificación de vulnerabilidades: {len(programas)} programas con versión, consulta NVD {modo}.")

    manual = cargar_cpe_manual(carpeta)
    resultados: List[Dict[str, Any]] = []
    for indice, programa in enumerate(programas, start=1):
        print(f"[{indice}/{len(programas)}] {programa['programa']} {programa['version']} ...")
        resultado = analizar_programa(cliente, programa, manual)
        resultados.append(resultado)
        afectados = sum(1 for v in resultado["vulnerabilidades"] if v["estado_version"] == AFECTADO)
        detalle = resultado["cpe_identificado"] or resultado["estado_identificacion"]
        print(f"    -> {detalle} | CVE: {len(resultado['vulnerabilidades'])} | afectados: {afectados}")
        cliente.guardar_cache()

    informe = {
        "equipo": equipo.get("equipo", "desconocido"),
        "ip": equipo.get("ip", "desconocida"),
        "generado_en": datetime.now().astimezone().isoformat(timespec="seconds"),
        "fuente": "NVD API 2.0 (services.nvd.nist.gov)",
        "aviso_nvd": AVISO_NVD,
        "advertencias": [
            "Una coincidencia de nombre no confirma la identidad del producto: revisar confianza_cpe.",
            "La ausencia de CVE no demuestra que un programa sea seguro.",
            "CVSS indica la gravedad técnica de la vulnerabilidad, no el riesgo real en este equipo.",
            "INDETERMINADO: no se ha podido determinar con los datos de la NVD si la versión está afectada.",
        ],
        "inventario": contadores,
        "resumen": construir_resumen(contadores["total_entradas"], programas, resultados),
        "resultados": resultados,
    }

    if guardar:
        guardar_json_atomico(carpeta / ARCHIVO_SALIDA, informe)
        print(f"Archivo {ARCHIVO_SALIDA} generado correctamente.")
    return informe


def resumen_compacto(informe: Dict[str, Any]) -> Dict[str, Any]:
    """Versión reducida de vulnerabilidades.json para el informe completo.

    El informe completo se acumula en registros.json en cada envío; incluir
    todas las descripciones (más de 1 MB con Chrome) lo haría crecer sin
    control. Aquí van el resumen y los CVE afectados/indeterminados con su
    CVSS; el detalle completo se envía a POST /api/vulnerabilidades.
    """
    programas = []
    for res in informe.get("resultados", []):
        cves = [
            {
                "cve_id": v["cve_id"],
                "estado_version": v["estado_version"],
                "score": (v["cvss"] or {}).get("score"),
                "severidad": (v["cvss"] or {}).get("severidad"),
            }
            for v in res.get("vulnerabilidades", [])
            if v["estado_version"] in (AFECTADO, INDETERMINADO)
        ]
        programas.append(
            {
                "programa": res.get("programa"),
                "version_instalada": res.get("version_instalada"),
                "cpe_identificado": res.get("cpe_identificado"),
                "estado_identificacion": res.get("estado_identificacion"),
                "estado_programa": res.get("estado_programa"),
                "cve": cves,
            }
        )
    return {
        "equipo": informe.get("equipo"),
        "generado_en": informe.get("generado_en"),
        "aviso_nvd": AVISO_NVD,
        "resumen": informe.get("resumen"),
        "programas": programas,
    }


def mostrar_resumen_vulnerabilidades(informe: Dict[str, Any]) -> None:
    """Imprime por consola el resumen del análisis."""
    r = informe["resumen"]
    linea = "=" * 50
    print(linea)
    print("IDENTIFICACIÓN DE SOFTWARE VULNERABLE (NVD)")
    print(linea)
    print(f"Programas en inventario:     {r['total_programas_analizados']}")
    print(f"Con versión analizable:      {r['programas_con_version']}")
    print(f"Identificados en CPE:        {r['programas_identificados_cpe']}")
    print(f"Sin coincidencia CPE:        {r['sin_coincidencia_cpe']}")
    print(f"Errores de consulta NVD:     {r['errores_consulta_nvd']}")
    print(f"Programas AFECTADOS:         {r['programas_afectados']}")
    print(f"Programas INDETERMINADOS:    {r['programas_indeterminados']}")
    print(f"CVE encontrados / afectados: {r['total_cve_encontrados']} / {r['cve_afectados']}")
    for res in informe["resultados"]:
        if res.get("estado_programa") == AFECTADO:
            print(f"- {res['programa']} {res['version_instalada']} ({res['cpe_identificado']})")
            afectados = [v for v in res["vulnerabilidades"] if v["estado_version"] == AFECTADO]
            for v in afectados[:MAX_CVE_CONSOLA]:
                cvss = v["cvss"] or {}
                print(f"    {v['cve_id']}  CVSS {cvss.get('version', '-')} {cvss.get('score', '-')} {cvss.get('severidad', '')}")
            if len(afectados) > MAX_CVE_CONSOLA:
                print(f"    ... y {len(afectados) - MAX_CVE_CONSOLA} CVE afectados más (ver {ARCHIVO_SALIDA})")
    print(AVISO_NVD)
    print(linea)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="SecureWatch Semana 10 - identificación de CVE (NVD)")
    parser.add_argument("--max", type=int, metavar="N", help="Analizar solo los N primeros programas")
    parser.add_argument("--sin-cache", action="store_true", help="No usar la caché local de respuestas NVD")
    args = parser.parse_args(argv)

    cliente = ClienteNVD(
        api_key=os.environ.get("NVD_API_KEY"),
        ruta_cache=CARPETA_PROGRAMA / ARCHIVO_CACHE,
        usar_cache=not args.sin_cache,
    )
    informe = analizar_vulnerabilidades(CARPETA_PROGRAMA, cliente=cliente, max_programas=args.max)
    mostrar_resumen_vulnerabilidades(informe)
    return 0


if __name__ == "__main__":
    sys.exit(main())
