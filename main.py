#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecureWatch - Semana 10: agente de seguridad, inventario, HEARTBEAT e
identificación de software vulnerable (API NVD 2.0).

Mantiene el análisis de la semana 7 y el envío del informe completo de la
semana 8, y añade:
- Identificación única del equipo mediante un UUID que se guarda en
  equipo_uuid.txt para que no cambie entre ejecuciones.
- Señal HEARTBEAT cada 30 segundos al servidor (POST /api/heartbeat) con el
  UUID, nombre, IP, sistema operativo, Security Score y nivel de riesgo.
- Control de errores de conexión: si el servidor no está disponible, el
  agente lo indica y sigue funcionando hasta que vuelva a estarlo.

Semana 10 (módulo identificacion.py):
- Con --identificar se normaliza software.json, se busca el CPE de cada
  programa y sus CVE en la API NVD 2.0, se compara la versión instalada con
  packaging.version y se genera vulnerabilidades.json.
- Un resumen compacto de vulnerabilidades.json se incluye en el informe
  completo (clave "vulnerabilidades") y el detalle completo se envía a
  POST /api/vulnerabilidades.
- Si existe la variable de entorno NVD_API_KEY, se usa (consultas más rápidas).

Uso:
    python main.py                  informe + HEARTBEAT continuo (Ctrl+C para parar)
    python main.py --solo-informe   comportamiento de la semana 8 (un envío y termina)
    python main.py --servidor 192.168.1.38   usar otro servidor sin editar el código
    python main.py --identificar    además identifica CVE del software instalado (semana 10)
    python main.py --identificar --solo-informe   identificación + un envío y termina
"""

import argparse
import contextlib
import io
import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

# Semana 10: identificación de vulnerabilidades. Se importa de forma tolerante
# para que el agente siga funcionando aunque falte el módulo o 'packaging'.
try:
    from identificacion import (
        analizar_vulnerabilidades,
        mostrar_resumen_vulnerabilidades,
        resumen_compacto,
    )
    ERROR_IMPORTACION_IDENTIFICACION: Optional[str] = None
except ImportError as _error_importacion:  # pragma: no cover
    analizar_vulnerabilidades = None  # type: ignore[assignment]
    mostrar_resumen_vulnerabilidades = None  # type: ignore[assignment]
    resumen_compacto = None  # type: ignore[assignment]
    ERROR_IMPORTACION_IDENTIFICACION = str(_error_importacion)

CARPETA_PROGRAMA = Path(__file__).resolve().parent

# Dirección del servidor central. Sustituir por la IP del equipo que ejecuta
# server.py, por ejemplo "192.168.1.38".
IP_SERVIDOR = "127.0.0.1"
PUERTO_SERVIDOR = 8000
URL_SERVIDOR = f"http://{IP_SERVIDOR}:{PUERTO_SERVIDOR}/api/equipos"

# Segundos que se espera la respuesta del servidor antes de darla por perdida.
TIEMPO_ESPERA = 5

# Semana 9: HEARTBEAT e identificación única.
INTERVALO_HEARTBEAT = 30          # segundos entre señales
ARCHIVO_UUID = "equipo_uuid.txt"  # identificador persistente del equipo


def configurar_servidor(ip: str) -> None:
    """Cambia la IP del servidor para el informe y el HEARTBEAT."""
    global IP_SERVIDOR, URL_SERVIDOR, URL_HEARTBEAT, URL_VULNERABILIDADES
    IP_SERVIDOR = ip
    URL_SERVIDOR = f"http://{IP_SERVIDOR}:{PUERTO_SERVIDOR}/api/equipos"
    URL_HEARTBEAT = f"http://{IP_SERVIDOR}:{PUERTO_SERVIDOR}/api/heartbeat"
    URL_VULNERABILIDADES = f"http://{IP_SERVIDOR}:{PUERTO_SERVIDOR}/api/vulnerabilidades"


URL_HEARTBEAT = f"http://{IP_SERVIDOR}:{PUERTO_SERVIDOR}/api/heartbeat"
URL_VULNERABILIDADES = f"http://{IP_SERVIDOR}:{PUERTO_SERVIDOR}/api/vulnerabilidades"
ARCHIVO_VULNERABILIDADES = "vulnerabilidades.json"

NIVELES = ("CRÍTICA", "ALTA", "MEDIA", "AVISO", "INFORMACIÓN")
PUNTOS_POR_NIVEL = {
    "CRÍTICA": 40,
    "ALTA": 25,
    "MEDIA": 15,
    "AVISO": 5,
    "INFORMACIÓN": 0,
}

# Corrección aplicada: ACTIVO/ACTIVADO no debe generar alerta.
FIREWALL_CON_PROBLEMA = ("DESACTIVADO",)
ANTIVIRUS_AUSENTE = ("NO DETECTADO", "NO_DETECTADO", "SIN ANTIVIRUS", "NONE", "NINGUNO")
SIN_COMPROBAR = ("NO COMPROBADO",)

UMBRAL_DISCO_ALTA = 10
UMBRAL_DISCO_AVISO = 20

PUERTOS_AVISO = {3389: "RDP", 445: "SMB"}
PUERTOS_INFORMACION = {22: "SSH", 80: "HTTP", 443: "HTTPS"}
NOMBRES_PUERTO = {
    22: "SSH",
    80: "HTTP",
    135: "RPC",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    5040: "Windows",
    7680: "Delivery Optimization",
}


def leer_json(nombre: str) -> Optional[Any]:
    ruta = CARPETA_PROGRAMA / nombre
    try:
        with open(ruta, "r", encoding="utf-8") as archivo:
            return json.load(archivo)
    except FileNotFoundError:
        print(f"Aviso: no se encontró {nombre}.")
        return None
    except (OSError, json.JSONDecodeError) as error:
        print(f"Aviso: no se pudo leer {nombre}: {error}")
        return None


def guardar_json(nombre: str, datos: Any) -> None:
    ruta = CARPETA_PROGRAMA / nombre
    with open(ruta, "w", encoding="utf-8") as archivo:
        json.dump(datos, archivo, ensure_ascii=False, indent=4)


def crear_alerta(tipo: str, nivel: str, mensaje: str) -> Dict[str, str]:
    return {"tipo": tipo, "nivel": nivel, "mensaje": mensaje}


def es_numero(valor: Any) -> bool:
    return isinstance(valor, (int, float)) and not isinstance(valor, bool)


def convertir_a_bool(valor: Any) -> Optional[bool]:
    if isinstance(valor, bool):
        return valor
    if isinstance(valor, int):
        if valor in (0, 1):
            return bool(valor)
        return None
    if isinstance(valor, str):
        texto = valor.strip().lower()
        if texto in ("true", "1", "sí", "si", "yes", "y", "habilitado", "enabled", "active", "activo"):
            return True
        if texto in ("false", "0", "no", "n", "deshabilitado", "disabled", "inactive", "inactivo"):
            return False
    return None


def normalizar_estado(datos: Any) -> str:
    if not isinstance(datos, dict):
        return "NO COMPROBADO"
    estado = str(datos.get("estado", "NO COMPROBADO")).strip().upper()
    return estado


def evaluar_firewall(seguridad: Dict[str, Any]) -> Tuple[List[Dict[str, str]], Optional[str]]:
    estado = seguridad.get("firewall")
    if not isinstance(estado, str):
        return [], "Firewall"
    estado_norm = estado.strip().upper()
    if estado_norm in SIN_COMPROBAR:
        return [], "Firewall"
    if estado_norm in FIREWALL_CON_PROBLEMA:
        return [crear_alerta("Firewall", "ALTA", "El firewall está desactivado")], None
    return [], None


def evaluar_antivirus(seguridad: Dict[str, Any]) -> Tuple[List[Dict[str, str]], Optional[str]]:
    antivirus = seguridad.get("antivirus")
    if not isinstance(antivirus, str):
        return [], "Antivirus"
    antivirus_norm = antivirus.strip().upper()
    if antivirus_norm in SIN_COMPROBAR:
        return [], "Antivirus"
    if antivirus_norm in ANTIVIRUS_AUSENTE:
        return [crear_alerta("Antivirus", "CRÍTICA", "No se ha detectado antivirus")], None
    return [], None


def evaluar_actualizaciones(actualizaciones: Dict[str, Any]) -> Tuple[List[Dict[str, str]], Optional[str]]:
    pendientes = actualizaciones.get("actualizaciones_pendientes")
    if not isinstance(pendientes, int) or isinstance(pendientes, bool):
        return [], "Actualizaciones"
    if pendientes <= 0:
        return [], None
    if pendientes <= 3:
        mensaje = "1 actualización pendiente" if pendientes == 1 else f"{pendientes} actualizaciones pendientes"
        return [crear_alerta("Actualizaciones", "MEDIA", mensaje)], None
    return [crear_alerta("Actualizaciones", "ALTA", f"{pendientes} actualizaciones pendientes (más de 3)")], None


def evaluar_disco(equipo: Dict[str, Any]) -> Tuple[List[Dict[str, str]], Optional[str]]:
    total = equipo.get("disco_total_gb")
    libre = equipo.get("disco_libre_gb")
    if not es_numero(total) or not es_numero(libre) or total <= 0:
        return [], "Espacio en disco"
    porcentaje = (libre / total) * 100
    detalle = f"{libre:.2f} GB libres de {total:.2f} GB ({porcentaje:.1f} %)"
    if porcentaje < UMBRAL_DISCO_ALTA:
        return [crear_alerta("Disco", "ALTA", f"Espacio libre por debajo del 10 %: {detalle}")], None
    if porcentaje < UMBRAL_DISCO_AVISO:
        return [crear_alerta("Disco", "AVISO", f"Espacio libre por debajo del 20 %: {detalle}")], None
    return [], None


def extraer_puertos(desde: Any) -> List[int]:
    if isinstance(desde, list):
        puertos: List[int] = []
        for elemento in desde:
            puertos.extend(extraer_puertos(elemento))
        return sorted(set(puertos))

    if isinstance(desde, dict):
        numero = desde.get("puerto", desde.get("port", desde.get("LocalPort")))
        if es_numero(numero):
            estado = str(desde.get("estado", desde.get("State", "ABIERTO"))).strip().upper()
            if estado in ("ABIERTO", "OPEN", "LISTENING", "ESCUCHANDO"):
                return [int(numero)]
        return []

    if es_numero(desde):
        return [int(desde)]

    return []


def evaluar_puertos(servicios: Dict[str, Any]) -> Tuple[List[Dict[str, str]], Optional[str]]:
    if normalizar_estado(servicios) == "NO COMPROBADO":
        return [], "Puertos"

    alertas: List[Dict[str, str]] = []
    puertos = extraer_puertos(servicios.get("puertos", []))

    for puerto in puertos:
        if puerto in PUERTOS_AVISO:
            servicio = PUERTOS_AVISO[puerto]
            alertas.append(
                crear_alerta(
                    "Puertos",
                    "AVISO",
                    f"Puerto {puerto} ({servicio}) abierto: revisar exposición",
                )
            )
        elif puerto in PUERTOS_INFORMACION:
            servicio = PUERTOS_INFORMACION[puerto]
            alertas.append(
                crear_alerta(
                    "Puertos",
                    "INFORMACIÓN",
                    f"Puerto {puerto} ({servicio}) detectado en escucha",
                )
            )

    return alertas, None


def _parece_ruta_valida(ruta: Any) -> bool:
    if not isinstance(ruta, str):
        return False
    texto = ruta.strip()
    if not texto:
        return False
    if len(texto) >= 3 and texto[1] == ":" and texto[2] in ("\\", "/"):
        return True
    return texto.startswith("\\\\")


def evaluar_arranque(arranque: Dict[str, Any]) -> Tuple[List[Dict[str, str]], Optional[str]]:
    if normalizar_estado(arranque) == "NO COMPROBADO":
        return [], "Arranque automático"

    programas = arranque.get("programas")
    servicios_auto = arranque.get("servicios_automaticos")
    if not isinstance(programas, list):
        programas = []
    if not isinstance(servicios_auto, list):
        servicios_auto = []

    alertas: List[Dict[str, str]] = []
    huerfanas = 0

    for programa in programas:
        if not isinstance(programa, dict):
            continue
        if convertir_a_bool(programa.get("huerfana")) is True:
            huerfanas += 1
            continue
        ruta = programa.get("ruta", programa.get("comando"))
        if ruta is not None and not _parece_ruta_valida(ruta):
            huerfanas += 1

    if huerfanas > 0:
        txt = "entrada huérfana" if huerfanas == 1 else "entradas huérfanas"
        alertas.append(crear_alerta("Arranque", "AVISO", f"Se detectaron {huerfanas} {txt} en inicio automático"))

    if programas or servicios_auto:
        alertas.append(
            crear_alerta(
                "Arranque",
                "INFORMACIÓN",
                f"Inventario de arranque: {len(programas)} programas y {len(servicios_auto)} servicios automáticos",
            )
        )

    return alertas, None


def _es_admin(nombre_grupo: Any) -> bool:
    if not isinstance(nombre_grupo, str):
        return False
    grupo = nombre_grupo.strip().lower()
    return grupo in ("administradores", "administrators")


def _es_invitado(nombre: Any) -> bool:
    if not isinstance(nombre, str):
        return False
    return nombre.strip().lower() in ("invitado", "guest")


def evaluar_cuentas(cuentas: Dict[str, Any]) -> Tuple[List[Dict[str, str]], Optional[str]]:
    if normalizar_estado(cuentas) == "NO COMPROBADO":
        return [], "Cuentas de usuario"

    lista_cuentas = cuentas.get("cuentas")
    if not isinstance(lista_cuentas, list):
        lista_cuentas = []

    alertas: List[Dict[str, str]] = []
    admins = 0

    for cuenta in lista_cuentas:
        if not isinstance(cuenta, dict):
            continue

        nombre = str(cuenta.get("nombre", cuenta.get("name", "Cuenta desconocida")))
        habilitada = convertir_a_bool(cuenta.get("habilitada", cuenta.get("enabled")))
        es_admin = convertir_a_bool(cuenta.get("es_administrador", cuenta.get("is_admin")))
        if es_admin is None:
            es_admin = _es_admin(cuenta.get("grupo", cuenta.get("group")))
        requiere_pwd = convertir_a_bool(cuenta.get("requiere_contrasena", cuenta.get("password_required")))

        if es_admin:
            admins += 1

        if habilitada is True and es_admin is True and requiere_pwd is False:
            alertas.append(
                crear_alerta(
                    "Cuentas",
                    "ALTA",
                    f"La cuenta administradora '{nombre}' está habilitada sin contraseña requerida",
                )
            )

        if habilitada is True and _es_invitado(nombre):
            alertas.append(crear_alerta("Cuentas", "ALTA", f"La cuenta invitada '{nombre}' está habilitada"))

    if admins > 2:
        alertas.append(crear_alerta("Cuentas", "AVISO", f"Hay {admins} cuentas con privilegios de administrador"))

    if lista_cuentas:
        alertas.append(crear_alerta("Cuentas", "INFORMACIÓN", f"Inventario local: {len(lista_cuentas)} cuentas analizadas"))

    return alertas, None


def _valor_cero_o_desactivado(valor: Any) -> bool:
    if valor is None:
        return True
    if isinstance(valor, (int, float)) and not isinstance(valor, bool):
        return valor <= 0
    if isinstance(valor, str):
        texto = valor.strip().lower()
        if texto in ("0", "none", "ninguno", "ninguna", "nunca", "never", "no", "false", "sin caducidad"):
            return True
        numero = re.findall(r"\d+", texto)
        if numero:
            return int(numero[0]) <= 0
    return False


def _unidad_protegida(unidad: Dict[str, Any]) -> Optional[bool]:
    protegido = convertir_a_bool(unidad.get("protegida", unidad.get("protected")))
    if protegido is not None:
        return protegido
    porcentaje = unidad.get("porcentaje_cifrado", unidad.get("EncryptionPercentage"))
    if es_numero(porcentaje):
        return float(porcentaje) > 0
    estado = unidad.get("estado_proteccion", unidad.get("ProtectionStatus"))
    if isinstance(estado, str):
        st = estado.strip().lower()
        if st in ("on", "activo", "activa", "enabled", "protegido", "protegida"):
            return True
        if st in ("off", "desactivado", "desactivada", "disabled", "sin proteger", "unprotected"):
            return False
    return None


def evaluar_cifrado(cifrado: Dict[str, Any]) -> Tuple[List[Dict[str, str]], Optional[str]]:
    if normalizar_estado(cifrado) == "NO COMPROBADO":
        return [], "Cifrado y contraseñas"

    unidades = cifrado.get("unidades")
    politica = cifrado.get("politica_contrasenas", cifrado.get("politica", {}))
    if not isinstance(unidades, list):
        unidades = []
    if not isinstance(politica, dict):
        politica = {}

    alertas: List[Dict[str, str]] = []

    for unidad in unidades:
        if not isinstance(unidad, dict):
            continue
        letra = str(unidad.get("unidad", unidad.get("MountPoint", ""))).strip().upper().replace("\\", "")
        protegida = _unidad_protegida(unidad)
        if protegida is None:
            continue
        if letra.startswith("C:") or letra == "C":
            if protegida is False:
                alertas.append(crear_alerta("Cifrado", "ALTA", "La unidad C: no tiene BitLocker activo"))
        elif protegida is False:
            alertas.append(crear_alerta("Cifrado", "AVISO", f"La unidad {letra or '?'} no está protegida"))

    longitud = politica.get("longitud_minima")
    if es_numero(longitud) and float(longitud) < 8:
        alertas.append(crear_alerta("Contraseñas", "MEDIA", f"Longitud mínima insuficiente ({int(longitud)})"))

    if _valor_cero_o_desactivado(politica.get("caducidad_dias")):
        alertas.append(crear_alerta("Contraseñas", "AVISO", "Las contraseñas no caducan"))

    if _valor_cero_o_desactivado(politica.get("historial")):
        alertas.append(crear_alerta("Contraseñas", "AVISO", "No hay historial de contraseñas"))

    if _valor_cero_o_desactivado(politica.get("bloqueo_intentos")):
        alertas.append(crear_alerta("Contraseñas", "AVISO", "No hay bloqueo tras intentos fallidos"))

    if unidades or politica:
        alertas.append(crear_alerta("Cifrado", "INFORMACIÓN", "Inventario de cifrado y política de contraseñas revisado"))

    return alertas, None


def contar_alertas(alertas: List[Dict[str, str]]) -> Dict[str, int]:
    resumen = {nivel: 0 for nivel in NIVELES}
    for alerta in alertas:
        nivel = alerta.get("nivel")
        if nivel in resumen:
            resumen[nivel] += 1
    return resumen


def calcular_puntos(alertas: List[Dict[str, str]]) -> int:
    puntos = 0
    for alerta in alertas:
        puntos += PUNTOS_POR_NIVEL.get(alerta.get("nivel", ""), 0)
    return puntos


def calcular_score(alertas: List[Dict[str, str]]) -> int:
    return max(0, 100 - calcular_puntos(alertas))


def clasificar_riesgo(puntos: int) -> str:
    if puntos == 0:
        return "BAJO"
    if 1 <= puntos <= 20:
        return "MODERADO"
    if 21 <= puntos <= 40:
        return "ALTO"
    return "CRÍTICO"


def mostrar_resumen(
    equipo: Dict[str, Any],
    alertas: List[Dict[str, str]],
    resumen: Dict[str, int],
    score: int,
    riesgo: str,
    sin_comprobar: List[str],
) -> None:
    linea = "=" * 50
    separador = "-" * 50

    print(linea)
    print("SECUREWATCH")
    print(linea)
    print("Equipo:", equipo.get("equipo", "desconocido"))
    print("Sistema:", equipo.get("sistema_operativo", "desconocido"))
    print("Usuario:", equipo.get("usuario", "desconocido"))
    print("IP:", equipo.get("ip", "desconocida"))
    print(separador)
    print("ESTADO DE SEGURIDAD")
    print(f"Security Score: {score}/100")
    print("Nivel de riesgo:", riesgo)
    print("Alertas detectadas:", len(alertas))
    for nivel in NIVELES:
        print(f"{nivel}: {resumen[nivel]}")
    print(separador)

    if alertas:
        print("ALERTAS")
        for alerta in alertas:
            print(f"[{alerta['nivel']}] {alerta['tipo']}")
            print(f"  {alerta['mensaje']}")
    else:
        print("No se han detectado alertas.")

    if sin_comprobar:
        print(separador)
        print("No se pudo comprobar:", ", ".join(sin_comprobar))

    print(linea)


def guardar_alertas(
    equipo: Dict[str, Any],
    alertas: List[Dict[str, str]],
    resumen: Dict[str, int],
    score: int,
    riesgo: str,
    sin_comprobar: List[str],
) -> None:
    salida = {
        "equipo": equipo.get("equipo", "desconocido"),
        "score": score,
        "riesgo": riesgo,
        "numero_alertas": len(alertas),
        "resumen": resumen,
        "alertas": alertas,
        "no_comprobadas": sin_comprobar,
    }
    guardar_json("alertas.json", salida)
    print("Archivo alertas.json generado correctamente: alertas.json")


def ejecutar_powershell_json(comando: str) -> Optional[Any]:
    if os.name != "nt":
        return None
    try:
        proceso = subprocess.run(
            ["powershell", "-NoProfile", "-Command", comando],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=40,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return None

    if proceso.returncode != 0:
        return None

    salida = proceso.stdout.strip()
    if not salida:
        return []

    try:
        return json.loads(salida)
    except json.JSONDecodeError:
        return None


def ejecutar_powershell_texto(comando: str) -> Optional[str]:
    if os.name != "nt":
        return None
    try:
        proceso = subprocess.run(
            ["powershell", "-NoProfile", "-Command", comando],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=40,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return None

    if proceso.returncode != 0:
        return None
    return proceso.stdout


def recolectar_servicios() -> None:
    if os.name != "nt":
        guardar_json("servicios.json", {"estado": "NO COMPROBADO", "puertos": []})
        return

    cmd = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        "Get-NetTCPConnection -State Listen | "
        "Select-Object LocalAddress,LocalPort,State,OwningProcess | ConvertTo-Json"
    )
    datos = ejecutar_powershell_json(cmd)
    if datos is None:
        guardar_json("servicios.json", {"estado": "NO COMPROBADO", "puertos": []})
        return

    if isinstance(datos, dict):
        datos = [datos]
    puertos = []
    for conexion in datos:
        if not isinstance(conexion, dict):
            continue
        numero = conexion.get("LocalPort")
        if es_numero(numero):
            numero_int = int(numero)
            puertos.append(
                {
                    "puerto": numero_int,
                    "servicio": NOMBRES_PUERTO.get(numero_int, "desconocido"),
                    "estado": "ABIERTO",
                    "direccion": conexion.get("LocalAddress", ""),
                    "proceso": conexion.get("OwningProcess"),
                }
            )
    guardar_json("servicios.json", {"estado": "COMPROBADO", "puertos": puertos})


def recolectar_arranque() -> None:
    if os.name != "nt":
        guardar_json("arranque.json", {"estado": "NO COMPROBADO", "programas": [], "servicios_automaticos": []})
        return

    cmd_programas = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        "Get-CimInstance Win32_StartupCommand | "
        "Select-Object Name,Command,Location,User | ConvertTo-Json"
    )
    cmd_servicios = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        "Get-Service | Where-Object {$_.StartType -eq 'Automatic'} | "
        "Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json"
    )

    programas = ejecutar_powershell_json(cmd_programas)
    servicios_auto = ejecutar_powershell_json(cmd_servicios)
    if programas is None or servicios_auto is None:
        guardar_json("arranque.json", {"estado": "NO COMPROBADO", "programas": [], "servicios_automaticos": []})
        return

    if isinstance(programas, dict):
        programas = [programas]
    if isinstance(servicios_auto, dict):
        servicios_auto = [servicios_auto]

    salida_programas = []
    for item in programas:
        if not isinstance(item, dict):
            continue
        comando = str(item.get("Command", "")).strip()
        salida_programas.append(
            {
                "nombre": item.get("Name", ""),
                "ruta": comando,
                "ubicacion": item.get("Location", ""),
                "usuario": item.get("User", ""),
                "huerfana": False if comando else True,
            }
        )

    salida_servicios = []
    for item in servicios_auto:
        if not isinstance(item, dict):
            continue
        salida_servicios.append(
            {
                "nombre": item.get("Name", ""),
                "descripcion": item.get("DisplayName", ""),
                "estado": item.get("Status", ""),
                "inicio": item.get("StartType", ""),
            }
        )

    guardar_json(
        "arranque.json",
        {"estado": "COMPROBADO", "programas": salida_programas, "servicios_automaticos": salida_servicios},
    )


def recolectar_cuentas() -> None:
    if os.name != "nt":
        guardar_json("cuentas.json", {"estado": "NO COMPROBADO", "cuentas": []})
        return

    cmd_usuarios = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        "Get-LocalUser | Select-Object Name,Enabled,PasswordRequired | ConvertTo-Json"
    )
    usuarios = ejecutar_powershell_json(cmd_usuarios)

    if usuarios is None:
        guardar_json("cuentas.json", {"estado": "NO COMPROBADO", "cuentas": []})
        return

    if isinstance(usuarios, dict):
        usuarios = [usuarios]

    grupos_admin: set = set()
    for grupo in ("Administradores", "Administrators"):
        cmd_grupo = (
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
            f"Get-LocalGroupMember -Group '{grupo}' | Select-Object Name | ConvertTo-Json"
        )
        miembros = ejecutar_powershell_json(cmd_grupo)
        if miembros is None:
            continue
        if isinstance(miembros, dict):
            miembros = [miembros]
        for miembro in miembros:
            if isinstance(miembro, dict):
                nombre = str(miembro.get("Name", "")).split("\\")[-1].strip()
                if nombre:
                    grupos_admin.add(nombre.lower())

    cuentas = []
    for usuario in usuarios:
        if not isinstance(usuario, dict):
            continue
        nombre = str(usuario.get("Name", "")).strip()
        cuentas.append(
            {
                "nombre": nombre,
                "habilitada": bool(usuario.get("Enabled", False)),
                "requiere_contrasena": bool(usuario.get("PasswordRequired", False)),
                "es_administrador": nombre.lower() in grupos_admin,
            }
        )

    guardar_json("cuentas.json", {"estado": "COMPROBADO", "cuentas": cuentas})


def _extraer_numero_politica(texto: str, patrones: List[str]) -> Optional[int]:
    for patron in patrones:
        m = re.search(patron, texto, flags=re.IGNORECASE)
        if not m:
            continue
        valor = m.group(1).strip()
        if valor.lower() in ("none", "ninguno", "ninguna", "never", "nunca"):
            return 0
        nums = re.findall(r"\d+", valor)
        if nums:
            return int(nums[0])
    return None


def recolectar_cifrado() -> None:
    if os.name != "nt":
        guardar_json(
            "cifrado.json",
            {"estado": "NO COMPROBADO", "unidades": [], "politica_contrasenas": {}},
        )
        return

    cmd_bitlocker = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        "Get-BitLockerVolume | "
        "Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage | ConvertTo-Json"
    )
    bitlocker = ejecutar_powershell_json(cmd_bitlocker)
    texto_politicas = ejecutar_powershell_texto("net accounts")

    if bitlocker is None or texto_politicas is None:
        guardar_json(
            "cifrado.json",
            {"estado": "NO COMPROBADO", "unidades": [], "politica_contrasenas": {}},
        )
        return

    if isinstance(bitlocker, dict):
        bitlocker = [bitlocker]

    unidades = []
    for unidad in bitlocker:
        if not isinstance(unidad, dict):
            continue
        porcentaje = unidad.get("EncryptionPercentage", 0)
        protegido = False
        if es_numero(porcentaje):
            protegido = float(porcentaje) > 0
        unidades.append(
            {
                "unidad": str(unidad.get("MountPoint", "")).strip(),
                "protegida": protegido,
                "porcentaje_cifrado": porcentaje if es_numero(porcentaje) else 0,
                "estado": unidad.get("VolumeStatus", ""),
            }
        )

    longitud = _extraer_numero_politica(
        texto_politicas,
        [
            r"Minimum password length\s*[:=]\s*(.+)",
            r"Longitud m[ií]nima de la contrase[ñn]a\s*[:=]\s*(.+)",
        ],
    )
    caducidad = _extraer_numero_politica(
        texto_politicas,
        [
            r"Maximum password age\s*[:=]\s*(.+)",
            r"Antig[uü]edad m[aá]xima de la contrase[ñn]a\s*[:=]\s*(.+)",
        ],
    )
    historial = _extraer_numero_politica(
        texto_politicas,
        [
            r"Length of password history maintained\s*[:=]\s*(.+)",
            r"Longitud del historial de contrase[ñn]as mantenido\s*[:=]\s*(.+)",
        ],
    )
    bloqueo = _extraer_numero_politica(
        texto_politicas,
        [
            r"Lockout threshold\s*[:=]\s*(.+)",
            r"Umbral de bloqueo\s*[:=]\s*(.+)",
        ],
    )

    politica = {
        "longitud_minima": 0 if longitud is None else longitud,
        "caducidad_dias": 0 if caducidad is None else caducidad,
        "historial": 0 if historial is None else historial,
        "bloqueo_intentos": 0 if bloqueo is None else bloqueo,
    }

    guardar_json("cifrado.json", {"estado": "COMPROBADO", "unidades": unidades, "politica_contrasenas": politica})


def recolectar_datos_windows() -> None:
    if os.name != "nt":
        print("Aviso: --recolectar solo está disponible en Windows. Se dejarán comprobaciones en NO COMPROBADO.")
    recolectar_servicios()
    recolectar_arranque()
    recolectar_cuentas()
    recolectar_cifrado()


def cargar_datos_base() -> Dict[str, Dict[str, Any]]:
    equipo = leer_json("equipo.json")
    seguridad = leer_json("seguridad.json")
    actualizaciones = leer_json("actualizaciones.json")

    return {
        "equipo": equipo if isinstance(equipo, dict) else {},
        "seguridad": seguridad if isinstance(seguridad, dict) else {},
        "actualizaciones": actualizaciones if isinstance(actualizaciones, dict) else {},
    }


def ejecutar_analisis() -> Tuple[List[Dict[str, str]], Dict[str, int], int, str, List[str], Dict[str, Any]]:
    datos = cargar_datos_base()

    servicios = leer_json("servicios.json")
    arranque = leer_json("arranque.json")
    cuentas = leer_json("cuentas.json")
    cifrado = leer_json("cifrado.json")

    if not isinstance(servicios, dict):
        servicios = {"estado": "NO COMPROBADO", "puertos": []}
    if not isinstance(arranque, dict):
        arranque = {"estado": "NO COMPROBADO", "programas": [], "servicios_automaticos": []}
    if not isinstance(cuentas, dict):
        cuentas = {"estado": "NO COMPROBADO", "cuentas": []}
    if not isinstance(cifrado, dict):
        cifrado = {"estado": "NO COMPROBADO", "unidades": [], "politica_contrasenas": {}}

    evaluaciones = [
        evaluar_firewall(datos["seguridad"]),
        evaluar_antivirus(datos["seguridad"]),
        evaluar_actualizaciones(datos["actualizaciones"]),
        evaluar_disco(datos["equipo"]),
        evaluar_puertos(servicios),
        evaluar_arranque(arranque),
        evaluar_cuentas(cuentas),
        evaluar_cifrado(cifrado),
    ]

    alertas: List[Dict[str, str]] = []
    sin_comprobar: List[str] = []

    for alertas_rule, no_comp in evaluaciones:
        alertas.extend(alertas_rule)
        if no_comp and no_comp not in sin_comprobar:
            sin_comprobar.append(no_comp)

    resumen = contar_alertas(alertas)
    puntos = calcular_puntos(alertas)
    score = calcular_score(alertas)
    riesgo = clasificar_riesgo(puntos)

    return alertas, resumen, score, riesgo, sin_comprobar, datos["equipo"]


def nombre_valido(valor: Any) -> Optional[str]:
    """Devuelve el nombre del equipo si sirve para identificar el informe.

    Se descarta el valor "desconocido" porque es el que usa mostrar_resumen()
    cuando no ha podido leer equipo.json. Si no se descartara, un equipo sin
    datos acabaría enviando un informe a nombre de "desconocido", que el
    servidor no podría atribuir a ninguna máquina.
    """
    if isinstance(valor, str):
        texto = valor.strip()
        if texto and texto.lower() != "desconocido":
            return texto
    return None


def construir_informe() -> Optional[Dict[str, Any]]:
    """Agrupa en un único objeto el contenido de los informes del equipo.

    Cada clave del objeto corresponde a uno de los archivos JSON generados en
    las semanas anteriores. Si alguno no se puede leer, leer_json ya lo avisa
    y su contenido se envía como null, para que el servidor vea que falta.

    Semana 10: si existe vulnerabilidades.json se añade con la clave
    "vulnerabilidades". Si no existe (no se ha ejecutado --identificar) se
    envía null sin avisar, porque es un análisis opcional.
    """
    archivos = {
        "datos_equipo": "equipo.json",
        "seguridad": "seguridad.json",
        "actualizaciones": "actualizaciones.json",
        "alertas": "alertas.json",
        "software": "software.json",
    }

    bloques: Dict[str, Any] = {}
    for clave, nombre in archivos.items():
        bloques[clave] = leer_json(nombre)

    if (CARPETA_PROGRAMA / ARCHIVO_VULNERABILIDADES).exists():
        vulnerabilidades = leer_json(ARCHIVO_VULNERABILIDADES)
        # Se envía la versión compacta (resumen + CVE afectados/indeterminados)
        # para no inflar registros.json; el detalle completo va aparte a
        # POST /api/vulnerabilidades.
        if isinstance(vulnerabilidades, dict) and resumen_compacto is not None:
            vulnerabilidades = resumen_compacto(vulnerabilidades)
        bloques["vulnerabilidades"] = vulnerabilidades
    else:
        bloques["vulnerabilidades"] = None

    # El nombre del equipo identifica el informe. Se toma de equipo.json y, si
    # no está disponible, de alertas.json, que también lo incluye.
    nombre_equipo = None
    datos_equipo = bloques.get("datos_equipo")
    if isinstance(datos_equipo, dict):
        nombre_equipo = nombre_valido(datos_equipo.get("equipo"))

    if not nombre_equipo:
        datos_alertas = bloques.get("alertas")
        if isinstance(datos_alertas, dict):
            nombre_equipo = nombre_valido(datos_alertas.get("equipo"))

    if not nombre_equipo:
        print("Error: no se ha podido determinar el nombre del equipo. No se envía el informe.")
        print("Comprueba que equipo.json está en la misma carpeta que main.py.")
        return None

    return {"equipo": nombre_equipo, **bloques}


def enviar_informe(informe: Dict[str, Any]) -> bool:
    """Envía el informe al servidor central y devuelve True si se ha guardado.

    Comprueba el código de respuesta HTTP y captura los errores de conexión
    para que el programa termine con un mensaje claro en lugar de una traza.
    """
    print(f"Enviando el informe de {informe['equipo']} a {URL_SERVIDOR} ...")

    try:
        respuesta = requests.post(URL_SERVIDOR, json=informe, timeout=TIEMPO_ESPERA)
    except requests.exceptions.ConnectionError:
        print(f"Error de conexión: no se ha podido contactar con el servidor en {URL_SERVIDOR}.")
        print("Comprueba que server.py está en ejecución, que la IP es correcta y que el")
        print("firewall del servidor permite la conexión entrante al puerto 8000.")
        return False
    except requests.exceptions.Timeout:
        print(f"Error: el servidor {URL_SERVIDOR} no ha respondido en {TIEMPO_ESPERA} segundos.")
        print("Comprueba la conectividad entre los dos equipos y que el servidor no esté bloqueado.")
        return False
    except requests.exceptions.RequestException as error:
        print(f"Error al enviar el informe: {error}")
        return False

    if 200 <= respuesta.status_code < 300:
        print(f"Informe aceptado por el servidor (HTTP {respuesta.status_code}).")
        try:
            datos = respuesta.json()
        except ValueError:
            datos = None
        if isinstance(datos, dict) and "total_registros" in datos:
            print(f"Registros almacenados en el servidor: {datos['total_registros']}.")
        return True

    print(f"El servidor ha rechazado el informe (HTTP {respuesta.status_code}).")
    print(f"Respuesta del servidor: {respuesta.text}")
    return False


# ---------------------------------------------------------------------------
# Semana 10: identificación de software vulnerable (NVD)
# ---------------------------------------------------------------------------

def ejecutar_identificacion() -> Optional[Dict[str, Any]]:
    """Ejecuta identificacion.py y devuelve el informe de vulnerabilidades.

    Cualquier fallo (módulo ausente, error inesperado) se informa y devuelve
    None: el resto del agente (informe y HEARTBEAT) sigue funcionando. Los
    errores de red con la NVD los gestiona el propio módulo programa a
    programa (estado ERROR_NVD).
    """
    if analizar_vulnerabilidades is None:
        print(f"Aviso: no se puede ejecutar la identificación de vulnerabilidades: "
              f"{ERROR_IMPORTACION_IDENTIFICACION}")
        print("Instala la dependencia con: python -m pip install packaging")
        return None

    try:
        informe = analizar_vulnerabilidades(CARPETA_PROGRAMA)
    except Exception as error:  # noqa: BLE001 - el agente no debe detenerse
        print(f"Error durante la identificación de vulnerabilidades: {error}")
        return None

    if mostrar_resumen_vulnerabilidades is not None:
        mostrar_resumen_vulnerabilidades(informe)
    return informe


def enviar_vulnerabilidades(informe: Dict[str, Any]) -> bool:
    """Envía vulnerabilidades.json a POST /api/vulnerabilidades.

    Mismo control de errores que enviar_informe(): nunca lanza excepciones.
    """
    print(f"Enviando vulnerabilidades de {informe.get('equipo')} a {URL_VULNERABILIDADES} ...")
    try:
        # Timeout mayor: el informe puede ocupar varios cientos de KB.
        respuesta = requests.post(URL_VULNERABILIDADES, json=informe, timeout=TIEMPO_ESPERA * 4)
    except requests.exceptions.RequestException as error:
        print(f"No se han podido enviar las vulnerabilidades: {error}")
        return False

    if 200 <= respuesta.status_code < 300:
        print(f"Vulnerabilidades aceptadas por el servidor (HTTP {respuesta.status_code}).")
        return True

    print(f"El servidor ha rechazado las vulnerabilidades (HTTP {respuesta.status_code}).")
    print(f"Respuesta del servidor: {respuesta.text}")
    return False


# ---------------------------------------------------------------------------
# Semana 9: identificación única y HEARTBEAT
# ---------------------------------------------------------------------------

def obtener_uuid() -> str:
    """Devuelve el UUID del equipo, creándolo la primera vez.

    Se usa uuid4 (aleatorio, 122 bits): la probabilidad de que dos equipos
    generen el mismo valor es despreciable y no expone datos del hardware,
    a diferencia de uuid1, que incluye la dirección MAC.

    El valor se guarda en equipo_uuid.txt, en la carpeta del programa. En las
    ejecuciones siguientes se lee de ese archivo, de modo que el equipo
    conserva siempre el mismo identificador. Si el archivo está dañado, se
    genera uno nuevo y se avisa.
    """
    ruta = CARPETA_PROGRAMA / ARCHIVO_UUID

    if ruta.exists():
        texto = ruta.read_text(encoding="utf-8").strip()
        try:
            return str(uuid.UUID(texto))
        except ValueError:
            print(f"Aviso: {ARCHIVO_UUID} no contiene un UUID válido; se genera uno nuevo.")

    nuevo = str(uuid.uuid4())
    ruta.write_text(nuevo + "\n", encoding="utf-8")
    print(f"Identificador nuevo generado y guardado en {ARCHIVO_UUID}: {nuevo}")
    return nuevo


def construir_heartbeat(id_equipo: str) -> Dict[str, Any]:
    """Prepara la señal HEARTBEAT con los datos que el servidor guarda.

    El Security Score y el nivel de riesgo se recalculan en cada señal con
    el mismo análisis de la semana 7, de modo que el inventario refleja
    cualquier cambio en los archivos del equipo sin reiniciar el agente.
    """
    # Los avisos de archivos opcionales ausentes ya se mostraron al arrancar;
    # se silencian aquí para no repetirlos cada 30 segundos.
    with contextlib.redirect_stdout(io.StringIO()):
        _alertas, _resumen, score, riesgo, _sin, equipo = ejecutar_analisis()
    return {
        "uuid": id_equipo,
        "nombre": nombre_valido(equipo.get("equipo")) or "desconocido",
        "ip": equipo.get("ip", "desconocida"),
        "sistema_operativo": equipo.get("sistema_operativo", "desconocido"),
        "security_score": score,
        "nivel_riesgo": riesgo,
    }


def enviar_heartbeat(señal: Dict[str, Any]) -> bool:
    """Envía una señal HEARTBEAT. Nunca lanza excepciones de red.

    Devuelve True si el servidor la ha aceptado y False en cualquier otro
    caso, para que el bucle principal siga funcionando aunque el servidor
    no esté disponible temporalmente.
    """
    hora = datetime.now().strftime("%H:%M:%S")
    try:
        respuesta = requests.post(URL_HEARTBEAT, json=señal, timeout=TIEMPO_ESPERA)
    except requests.exceptions.ConnectionError:
        print(f"[{hora}] HEARTBEAT no entregado: servidor no disponible en {URL_HEARTBEAT}. "
              f"Reintento en {INTERVALO_HEARTBEAT} s.")
        return False
    except requests.exceptions.Timeout:
        print(f"[{hora}] HEARTBEAT no entregado: el servidor no respondió en {TIEMPO_ESPERA} s. "
              f"Reintento en {INTERVALO_HEARTBEAT} s.")
        return False
    except requests.exceptions.RequestException as error:
        print(f"[{hora}] HEARTBEAT no entregado: {error}. Reintento en {INTERVALO_HEARTBEAT} s.")
        return False

    if 200 <= respuesta.status_code < 300:
        try:
            mensaje = respuesta.json().get("mensaje", "")
        except ValueError:
            mensaje = ""
        print(f"[{hora}] HEARTBEAT OK (HTTP {respuesta.status_code}) "
              f"score={señal['security_score']} riesgo={señal['nivel_riesgo']}. {mensaje}")
        return True

    print(f"[{hora}] HEARTBEAT rechazado (HTTP {respuesta.status_code}): {respuesta.text}")
    return False


def bucle_heartbeat(id_equipo: str) -> None:
    """Envía una señal cada INTERVALO_HEARTBEAT segundos hasta Ctrl+C.

    El intervalo se mide desde el inicio de cada envío, de modo que el
    tiempo de respuesta del servidor no retrasa las señales siguientes.
    """
    print(f"HEARTBEAT activo cada {INTERVALO_HEARTBEAT} s hacia {URL_HEARTBEAT}. "
          "Pulsa Ctrl+C para detener el agente.")
    conectado: Optional[bool] = None

    while True:
        inicio = time.monotonic()
        ok = enviar_heartbeat(construir_heartbeat(id_equipo))

        if conectado is False and ok:
            print("Conexión con el servidor recuperada.")
        conectado = ok

        espera = INTERVALO_HEARTBEAT - (time.monotonic() - inicio)
        if espera > 0:
            time.sleep(espera)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="SecureWatch Semana 10")
    parser.add_argument("--recolectar", action="store_true", help="Recolectar datos del sistema (Windows)")
    parser.add_argument("--solo-informe", action="store_true",
                        help="Enviar el informe completo y terminar, sin HEARTBEAT (semana 8)")
    parser.add_argument("--servidor", metavar="IP", help="IP del servidor central (por defecto IP_SERVIDOR)")
    parser.add_argument("--identificar", "--vulnerabilidades", dest="identificar", action="store_true",
                        help="Identificar CVE del software instalado con la API NVD 2.0 (semana 10)")
    args = parser.parse_args(argv)

    if args.servidor:
        configurar_servidor(args.servidor)

    id_equipo = obtener_uuid()
    print(f"UUID del equipo: {id_equipo}")

    if args.recolectar:
        recolectar_datos_windows()

    alertas, resumen, score, riesgo, sin_comprobar, equipo = ejecutar_analisis()
    mostrar_resumen(equipo, alertas, resumen, score, riesgo, sin_comprobar)
    guardar_alertas(equipo, alertas, resumen, score, riesgo, sin_comprobar)

    # Semana 10: genera vulnerabilidades.json antes de construir el informe,
    # para que viaje dentro de él con la clave "vulnerabilidades".
    informe_vulnerabilidades = ejecutar_identificacion() if args.identificar else None

    informe = construir_informe()
    if informe is None:
        return 1

    # El informe completo incluye ahora también el UUID del equipo.
    informe["uuid"] = id_equipo
    informe_enviado = enviar_informe(informe)

    if informe_vulnerabilidades is not None:
        enviar_vulnerabilidades(informe_vulnerabilidades)

    if args.solo_informe:
        return 0 if informe_enviado else 1

    # Aunque el informe no se haya podido entregar, el agente sigue en marcha:
    # el HEARTBEAT reintentará cada 30 s hasta que el servidor responda.
    try:
        bucle_heartbeat(id_equipo)
    except KeyboardInterrupt:
        print("\nAgente detenido por el usuario. Se dejan de enviar señales HEARTBEAT.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
