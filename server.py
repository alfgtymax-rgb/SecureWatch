#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecureWatch - Semana 9: servidor central.

Mantiene la recepción y almacenamiento de informes completos (Semana 8) y añade:
- POST /api/heartbeat : recibe señales periódicas de los agentes y actualiza
  el inventario centralizado sin crear duplicados (upsert por UUID).
- GET  /api/inventario: devuelve el inventario con el estado calculado
  automáticamente (ONLINE si la última comunicación fue hace menos de 90 s,
  OFFLINE en caso contrario).

El inventario se persiste en inventario.json. Los informes completos siguen
guardándose en registros.json como en la Semana 8.

Ejecución:
    python -m uvicorn server:app --host 0.0.0.0 --port 8000

Documentación interactiva de la API:
    http://127.0.0.1:8000/docs
"""

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Body, FastAPI, HTTPException

CARPETA_PROGRAMA = Path(__file__).resolve().parent
ARCHIVO_REGISTROS = CARPETA_PROGRAMA / "registros.json"
ARCHIVO_INVENTARIO = CARPETA_PROGRAMA / "inventario.json"

# Un equipo pasa a OFFLINE si no ha enviado señal en más de 90 segundos.
UMBRAL_OFFLINE_SEGUNDOS = 90

# Bloqueos independientes para cada archivo de persistencia.
BLOQUEO = threading.Lock()
BLOQUEO_INVENTARIO = threading.Lock()

app = FastAPI(
    title="SecureWatch - Servidor central",
    description=(
        "Recepción y consulta de los informes de seguridad enviados por los "
        "equipos de la red. Incluye inventario centralizado y control de "
        "disponibilidad mediante señales HEARTBEAT (Semana 9)."
    ),
    version="2.0",
)


# ---------------------------------------------------------------------------
# Persistencia: registros de informes completos (Semana 8, sin cambios)
# ---------------------------------------------------------------------------

def leer_registros() -> List[Dict[str, Any]]:
    """Devuelve la lista de informes guardados en registros.json.

    - Si el archivo no existe, devuelve una lista vacía.
    - Si está vacío, lo trata como lista sin registros y avisa por consola.
    - Si el contenido no es JSON válido o no es una lista, lanza ValueError.
    """
    if not ARCHIVO_REGISTROS.exists():
        return []

    texto = ARCHIVO_REGISTROS.read_text(encoding="utf-8")

    if not texto.strip():
        print(f"Aviso: {ARCHIVO_REGISTROS.name} está vacío; "
              "se trata como una lista sin registros.")
        return []

    try:
        datos = json.loads(texto)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"{ARCHIVO_REGISTROS.name} no contiene JSON válido ({error})."
        ) from error

    if not isinstance(datos, list):
        raise ValueError(
            f"{ARCHIVO_REGISTROS.name} debería contener una lista JSON "
            f"y contiene {type(datos).__name__}."
        )

    return datos


def guardar_registros(registros: List[Dict[str, Any]]) -> None:
    """Escribe la lista completa en registros.json de forma atómica."""
    temporal = ARCHIVO_REGISTROS.with_suffix(".json.tmp")

    with open(temporal, "w", encoding="utf-8") as archivo:
        json.dump(registros, archivo, ensure_ascii=False, indent=4)
        archivo.write("\n")

    os.replace(temporal, ARCHIVO_REGISTROS)


# ---------------------------------------------------------------------------
# Persistencia: inventario centralizado (Semana 9)
# ---------------------------------------------------------------------------

def leer_inventario() -> Dict[str, Any]:
    """Devuelve el inventario de equipos guardado en inventario.json.

    El inventario es un diccionario cuya clave es el UUID de cada equipo.
    Si el archivo no existe o está vacío, devuelve un diccionario vacío.
    Si el contenido no es JSON válido o no es un dict, lanza ValueError.
    """
    if not ARCHIVO_INVENTARIO.exists():
        return {}

    texto = ARCHIVO_INVENTARIO.read_text(encoding="utf-8")

    if not texto.strip():
        return {}

    try:
        datos = json.loads(texto)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"{ARCHIVO_INVENTARIO.name} no contiene JSON válido ({error})."
        ) from error

    if not isinstance(datos, dict):
        raise ValueError(
            f"{ARCHIVO_INVENTARIO.name} debería contener un objeto JSON "
            f"y contiene {type(datos).__name__}."
        )

    return datos


def guardar_inventario(inventario: Dict[str, Any]) -> None:
    """Escribe el inventario completo en inventario.json de forma atómica."""
    temporal = ARCHIVO_INVENTARIO.with_suffix(".json.tmp")

    with open(temporal, "w", encoding="utf-8") as archivo:
        json.dump(inventario, archivo, ensure_ascii=False, indent=4)
        archivo.write("\n")

    os.replace(temporal, ARCHIVO_INVENTARIO)


# ---------------------------------------------------------------------------
# Lógica de disponibilidad
# ---------------------------------------------------------------------------

def calcular_estado(ultima_comunicacion_iso: Optional[str]) -> Dict[str, Any]:
    """Calcula el estado ONLINE/OFFLINE a partir de la última comunicación.

    El estado se calcula en el momento de cada consulta al inventario, no al
    recibir el heartbeat, de modo que refleja siempre la situación actual.

    Criterios:
    - Menos de 90 segundos sin comunicación → ONLINE.
    - Más de 90 segundos sin comunicación   → OFFLINE.
    - Fecha no interpretable                → OFFLINE.
    """
    if ultima_comunicacion_iso is None:
        return {"estado": "OFFLINE", "segundos_sin_contacto": None}

    try:
        ultima = datetime.fromisoformat(ultima_comunicacion_iso)
    except (ValueError, TypeError):
        return {"estado": "OFFLINE", "segundos_sin_contacto": None}

    # Comparar en la misma zona horaria que la fecha almacenada.
    ahora = datetime.now(tz=timezone.utc).astimezone(ultima.tzinfo or timezone.utc)
    segundos = (ahora - ultima).total_seconds()

    estado = "ONLINE" if segundos < UMBRAL_OFFLINE_SEGUNDOS else "OFFLINE"
    return {"estado": estado, "segundos_sin_contacto": int(segundos)}


# ---------------------------------------------------------------------------
# Endpoints: informes completos (Semana 8, sin cambios)
# ---------------------------------------------------------------------------

@app.post("/api/equipos", status_code=201)
def recibir_informe(informe: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Recibe el informe completo de un equipo y lo añade a registros.json.

    El cuerpo de la petición es el objeto JSON que envía main.py: el nombre
    del equipo y los cinco bloques de información. Se guarda tal cual dentro
    del campo "informe", junto a la identificación del equipo y la fecha y
    hora de recepción.
    """
    equipo = informe.get("equipo")

    if not isinstance(equipo, str) or not equipo.strip():
        raise HTTPException(
            status_code=422,
            detail="El informe debe incluir el campo 'equipo' con el nombre del equipo.",
        )

    registro = {
        "equipo": equipo.strip(),
        "recibido_en": datetime.now().astimezone().isoformat(timespec="seconds"),
        "informe": informe,
    }

    with BLOQUEO:
        try:
            registros = leer_registros()
        except ValueError as error:
            raise HTTPException(
                status_code=500,
                detail=(
                    f"No se ha guardado el informe: {error} "
                    "Revisa el archivo antes de continuar."
                ),
            ) from error

        registros.append(registro)

        try:
            guardar_registros(registros)
        except OSError as error:
            raise HTTPException(
                status_code=500,
                detail=f"No se ha podido escribir {ARCHIVO_REGISTROS.name}: {error}",
            ) from error

    print(
        f"Informe recibido de {registro['equipo']} "
        f"({registro['recibido_en']}). "
        f"Registros almacenados: {len(registros)}."
    )

    return {
        "mensaje": "Informe recibido y guardado.",
        "equipo": registro["equipo"],
        "recibido_en": registro["recibido_en"],
        "total_registros": len(registros),
    }


@app.get("/api/equipos")
def listar_informes() -> List[Dict[str, Any]]:
    """Devuelve todos los informes completos recibidos, en el orden de llegada."""
    try:
        return leer_registros()
    except ValueError as error:
        raise HTTPException(
            status_code=500,
            detail=f"No se han podido leer los registros: {error}",
        ) from error


# ---------------------------------------------------------------------------
# Endpoints: inventario y HEARTBEAT (Semana 9)
# ---------------------------------------------------------------------------

@app.post("/api/heartbeat", status_code=200)
def recibir_heartbeat(datos: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Recibe la señal HEARTBEAT periódica de un agente y actualiza su registro.

    Cada señal incluye el UUID del equipo. Si ya existe un registro con ese
    UUID, se actualiza sin crear uno nuevo (upsert). Si no existe, se crea.

    Campos esperados en el cuerpo JSON:
    - uuid             (str, obligatorio): identificador único del equipo.
    - nombre           (str): nombre del equipo.
    - ip               (str): dirección IP del equipo.
    - sistema_operativo(str): nombre del sistema operativo.
    - security_score   (int): puntuación de seguridad (0-100).
    - nivel_riesgo     (str): BAJO / MODERADO / ALTO / CRÍTICO.
    """
    uuid_equipo = datos.get("uuid")

    if not isinstance(uuid_equipo, str) or not uuid_equipo.strip():
        raise HTTPException(
            status_code=422,
            detail="La señal HEARTBEAT debe incluir el campo 'uuid'.",
        )

    uuid_equipo = uuid_equipo.strip()
    ahora = datetime.now().astimezone().isoformat(timespec="seconds")

    registro = {
        "uuid": uuid_equipo,
        "nombre": str(datos.get("nombre", "desconocido")).strip(),
        "ip": str(datos.get("ip", "desconocida")).strip(),
        "sistema_operativo": str(datos.get("sistema_operativo", "desconocido")).strip(),
        "security_score": datos.get("security_score", 0),
        "nivel_riesgo": str(datos.get("nivel_riesgo", "DESCONOCIDO")).strip(),
        "ultima_comunicacion": ahora,
    }

    with BLOQUEO_INVENTARIO:
        try:
            inventario = leer_inventario()
        except ValueError as error:
            raise HTTPException(
                status_code=500,
                detail=f"No se ha podido leer el inventario: {error}",
            ) from error

        es_nuevo = uuid_equipo not in inventario
        inventario[uuid_equipo] = registro

        try:
            guardar_inventario(inventario)
        except OSError as error:
            raise HTTPException(
                status_code=500,
                detail=(
                    f"No se ha podido escribir {ARCHIVO_INVENTARIO.name}: {error}"
                ),
            ) from error

    accion = "registrado" if es_nuevo else "actualizado"
    print(
        f"[HEARTBEAT] {accion.upper()}: {registro['nombre']} "
        f"| UUID …{uuid_equipo[-8:]} "
        f"| Score {registro['security_score']} "
        f"| Riesgo {registro['nivel_riesgo']} "
        f"| {ahora}"
    )

    return {
        "mensaje": f"Equipo {accion} en el inventario.",
        "uuid": uuid_equipo,
        "nombre": registro["nombre"],
        "ultima_comunicacion": ahora,
    }


@app.get("/api/inventario")
def listar_inventario() -> List[Dict[str, Any]]:
    """Devuelve el inventario centralizado con el estado ONLINE/OFFLINE calculado.

    El estado se calcula en el momento de la consulta comparando la fecha y
    hora de la última comunicación de cada equipo con la hora actual:
    - Menos de 90 segundos sin comunicación → ONLINE.
    - Más de 90 segundos sin comunicación   → OFFLINE.

    Campos devueltos por equipo:
    uuid, nombre, ip, sistema_operativo, security_score, nivel_riesgo,
    ultima_comunicacion, estado, segundos_sin_contacto.
    """
    try:
        inventario = leer_inventario()
    except ValueError as error:
        raise HTTPException(
            status_code=500,
            detail=f"No se ha podido leer el inventario: {error}",
        ) from error

    resultado = []
    for _uuid, equipo in inventario.items():
        equipo_con_estado = dict(equipo)
        estado_info = calcular_estado(equipo.get("ultima_comunicacion"))
        equipo_con_estado.update(estado_info)
        resultado.append(equipo_con_estado)

    return resultado
