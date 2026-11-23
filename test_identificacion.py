#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecureWatch - Semana 10: tests de identificacion.py.

No llaman a la API real: usan respuestas REALES de la NVD guardadas en
fixtures/ (descargadas el 23/11/2026 de services.nvd.nist.gov):

- cpe_winrar.json            keywordSearch=winrar
- cpe_vlc.json               keywordSearch=vlc media player
- cpe_configurador_fnmt.json keywordSearch=configurador fnmt (0 resultados)
- cves_winrar_6.00.json      virtualMatchString=cpe:2.3:a:rarlab:winrar:6.00 (7 CVE)
- cve_2023_40477.json        cveId=CVE-2023-40477 (WinRAR, CVSS 3.0)
- cve_2024_46461.json        cveId=CVE-2024-46461 (VLC, solo datos del CNA)
- cves_vlc_3.0.24.json       virtualMatchString=...vlc_media_player:3.0.24 (0 resultados)

Ejecución:
    python -m pytest -v test_identificacion.py
    python -m unittest -v test_identificacion
"""

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

import identificacion as ident

CARPETA_FIXTURES = Path(__file__).resolve().parent / "fixtures"


def cargar_fixture(nombre: str) -> Dict[str, Any]:
    with open(CARPETA_FIXTURES / nombre, "r", encoding="utf-8") as archivo:
        return json.load(archivo)


class RespuestaFalsa:
    """Imita lo mínimo de requests.Response."""

    def __init__(self, codigo: int, datos: Optional[Dict[str, Any]] = None) -> None:
        self.status_code = codigo
        self._datos = datos
        self.headers: Dict[str, str] = {}

    def json(self) -> Dict[str, Any]:
        if self._datos is None:
            raise ValueError("sin JSON")
        return self._datos


class SesionFixtures:
    """Sesión que responde con fixtures según los parámetros de la petición."""

    def __init__(self, mapa_cpe: Dict[str, str], mapa_cve: Dict[str, str]) -> None:
        self.mapa_cpe = mapa_cpe
        self.mapa_cve = mapa_cve
        self.peticiones: List[Dict[str, Any]] = []

    def get(self, url, params=None, headers=None, timeout=None):
        params = params or {}
        self.peticiones.append({"url": url, "params": dict(params), "headers": dict(headers or {})})
        if url == ident.URL_CPES:
            nombre = self.mapa_cpe.get(params["keywordSearch"].lower(), "cpe_configurador_fnmt.json")
            return RespuestaFalsa(200, cargar_fixture(nombre))
        nombre = self.mapa_cve.get(params.get("virtualMatchString"))
        if nombre is None:
            return RespuestaFalsa(200, cargar_fixture("cves_vlc_3.0.24.json"))
        return RespuestaFalsa(200, cargar_fixture(nombre))


class SesionSecuencia:
    """Devuelve respuestas (o lanza excepciones) en el orden indicado."""

    def __init__(self, respuestas: List[Any]) -> None:
        self.respuestas = list(respuestas)
        self.llamadas = 0

    def get(self, url, params=None, headers=None, timeout=None):
        self.llamadas += 1
        siguiente = self.respuestas.pop(0)
        if isinstance(siguiente, Exception):
            raise siguiente
        return siguiente


def crear_cliente(sesion: Any, api_key: Optional[str] = None) -> ident.ClienteNVD:
    esperas: List[float] = []
    cliente = ident.ClienteNVD(api_key=api_key, sesion=sesion, dormir=esperas.append, usar_cache=False)
    cliente.esperas = esperas  # type: ignore[attr-defined]
    return cliente


MAPA_CPE = {"winrar": "cpe_winrar.json", "vlc media player": "cpe_vlc.json"}
MAPA_CVE = {
    "cpe:2.3:a:rarlab:winrar:6.00": "cves_winrar_6.00.json",
    "cpe:2.3:a:videolan:vlc_media_player:3.0.24": "cves_vlc_3.0.24.json",
}


class TestNormalizacion(unittest.TestCase):

    def test_limpieza_y_duplicados(self):
        software = [
            {"Name": "WinRAR 7.13 (64-bit)", "Version": "7.13.0"},
            {"Name": "WinRAR versión 6.00", "Version": "6.00"},
            {"Name": "Microsoft Office LTSC Professional Plus 2021 - en-us", "Version": "16.0.1"},
            {"Name": "Microsoft Office LTSC Professional Plus 2021 - es-es", "Version": "16.0.1"},
            {"Name": "Spyder 6", "Version": "6.1.7"},
            {"Name": "Zoom Workplace", "Version": "7.2.0 (48358)"},
            {"Name": "Programa sin versión", "Version": None},
            {"Name": "Otro", "Version": ""},
        ]
        programas, contadores = ident.normalizar_inventario(software)
        nombres = [(p["programa"], p["version"]) for p in programas]
        self.assertIn(("WinRAR", "7.13.0"), nombres)
        self.assertIn(("WinRAR", "6.00"), nombres)
        self.assertIn(("Microsoft Office LTSC Professional Plus 2021", "16.0.1"), nombres)
        self.assertIn(("Spyder", "6.1.7"), nombres)
        self.assertIn(("Zoom Workplace", "7.2.0"), nombres)
        self.assertEqual(contadores, {"total_entradas": 8, "sin_version": 2, "duplicados": 1})

    def test_versiones_no_se_comparan_como_texto(self):
        # Como cadena "10.0" < "9.0"; con packaging 10.0 > 9.0.
        rango = {"hasta_excluido": "9.0"}
        self.assertFalse(ident.version_en_rango(ident.Version("10.0"), rango))
        self.assertTrue(ident.version_en_rango(ident.Version("6.00"), {"hasta_excluido": "6.23"}))
        self.assertFalse(ident.version_en_rango(ident.Version("6.100"), {"hasta_excluido": "6.23"}))


class TestVersionAfectada(unittest.TestCase):
    """(a) Versión afectada detectada con CVE reales de WinRAR."""

    def test_winrar_600_afectado(self):
        cliente = crear_cliente(SesionFixtures(MAPA_CPE, MAPA_CVE))
        programa = {"programa": "WinRAR", "nombre_original": "WinRAR versión 6.00", "version": "6.00"}
        resultado = ident.analizar_programa(cliente, programa)

        self.assertEqual(resultado["estado_identificacion"], ident.IDENTIFICADO)
        self.assertEqual(resultado["cpe_identificado"], "cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*")
        self.assertEqual(resultado["fabricante_detectado"], "rarlab")
        self.assertEqual(resultado["estado_programa"], ident.AFECTADO)

        ids = {v["cve_id"]: v for v in resultado["vulnerabilidades"]}
        self.assertEqual(len(ids), 7)
        self.assertTrue(all(v["estado_version"] == ident.AFECTADO for v in ids.values()))

        cve = ids["CVE-2023-38831"]
        self.assertEqual(cve["cvss"]["version"], "3.1")
        self.assertEqual(cve["cvss"]["score"], 7.8)
        self.assertEqual(cve["cvss"]["severidad"], "HIGH")
        self.assertEqual(cve["versiones_afectadas"][0]["hasta_excluido"], "6.23")
        self.assertTrue(cve["descripcion"])
        self.assertLessEqual(len(cve["referencias"]), ident.MAX_REFERENCIAS)

        # CVE-2025-8088 incluye también dtSearch: solo cuenta el rango de WinRAR.
        rangos_8088 = ids["CVE-2025-8088"]["versiones_afectadas"]
        self.assertEqual([r["hasta_excluido"] for r in rangos_8088], ["7.13"])

    def test_misma_respuesta_version_corregida_no_afectada(self):
        # Los mismos CVE reales evaluados con la versión 7.13.0 instalada.
        datos = cargar_fixture("cves_winrar_6.00.json")
        for item in datos["vulnerabilities"]:
            entrada = ident.analizar_cve(item, "rarlab", "winrar", "7.13.0")
            self.assertEqual(entrada["estado_version"], ident.NO_AFECTADO, entrada["cve_id"])

    def test_cvss_30_cuando_no_hay_31(self):
        item = cargar_fixture("cve_2023_40477.json")["vulnerabilities"][0]
        entrada = ident.analizar_cve(item, "rarlab", "winrar", "6.00")
        self.assertEqual(entrada["cvss"]["version"], "3.0")
        self.assertEqual(entrada["estado_version"], ident.AFECTADO)

    def test_rangos_de_otras_plataformas_se_ignoran(self):
        # CVE-2025-21338: rangos de microsoft:office para iPhone, Android y
        # macOS (no aplican) y "universal" (< 16.0.14326.22175).
        item = cargar_fixture("cve_2025_21338.json")["vulnerabilities"][0]
        instalada = ident.analizar_cve(item, "microsoft", "office", "16.0.14334.20974")
        antigua = ident.analizar_cve(item, "microsoft", "office", "16.0.14000.1000")
        self.assertEqual(instalada["estado_version"], ident.NO_AFECTADO)
        self.assertEqual(antigua["estado_version"], ident.AFECTADO)
        self.assertEqual([r["hasta_excluido"] for r in instalada["versiones_afectadas"]], ["16.0.14326.22175"])

    def test_cve_solo_con_datos_cna(self):
        # CVE-2024-46461 está "Deferred": sin configurations, solo datos del CNA.
        item = cargar_fixture("cve_2024_46461.json")["vulnerabilities"][0]
        afectado = ident.analizar_cve(item, "videolan", "vlc_media_player", "3.0.20")
        corregido = ident.analizar_cve(item, "videolan", "vlc_media_player", "3.0.24")
        self.assertEqual(afectado["estado_version"], ident.AFECTADO)
        self.assertEqual(corregido["estado_version"], ident.NO_AFECTADO)
        self.assertEqual(afectado["versiones_afectadas"][0]["hasta_incluido"], "3.0.20")
        self.assertEqual(afectado["versiones_afectadas"][0]["origen"], "CNA")


class TestSinCoincidencia(unittest.TestCase):
    """(b) Producto sin coincidencia CPE."""

    def test_configurador_fnmt(self):
        sesion = SesionFixtures(MAPA_CPE, MAPA_CVE)
        cliente = crear_cliente(sesion)
        programa = {"programa": "Configurador FNMT", "nombre_original": "Configurador FNMT", "version": "5.1.2"}
        resultado = ident.analizar_programa(cliente, programa)
        self.assertEqual(resultado["estado_identificacion"], ident.SIN_COINCIDENCIA_CPE)
        self.assertIsNone(resultado["cpe_identificado"])
        self.assertEqual(resultado["vulnerabilidades"], [])
        self.assertIn("NO demuestra", resultado["nota"])
        # No se consulta cves/2.0 si no hay CPE.
        self.assertTrue(all(p["url"] == ident.URL_CPES for p in sesion.peticiones))

    def test_falsos_positivos_por_nombre(self):
        # Casos detectados con el inventario real del equipo.
        self.assertEqual(ident.puntuar_candidato("Comet", "cometd", "cometd", "CometD"), 0.0)
        self.assertEqual(ident.puntuar_candidato("Copilot", "microsoft", "365_copilot", "Microsoft 365 Copilot"), 0.0)
        self.assertEqual(
            ident.puntuar_candidato("HP Color LaserJet Pro M453-4 Ayuda", "hp", "color_laserjet_2500_toolbox",
                                    "HP Color LaserJet 2500 Toolbox"),
            0.0,
        )
        self.assertGreaterEqual(ident.puntuar_candidato("Microsoft Edge", "microsoft", "edge", "Microsoft Edge"),
                                ident.UMBRAL_CONFIANZA_ALTA)

    def test_nombre_parecido_no_basta(self):
        # Los CPE de VLC no deben aceptarse para un programa distinto.
        productos = cargar_fixture("cpe_vlc.json")["products"]
        mejor, _ = ident.elegir_cpe("Disney+", productos)
        self.assertIsNone(mejor)


class TestIndeterminado(unittest.TestCase):
    """(c) Versión indeterminada."""

    def test_version_no_interpretable(self):
        datos = cargar_fixture("cves_winrar_6.00.json")
        item = datos["vulnerabilities"][0]
        entrada = ident.analizar_cve(item, "rarlab", "winrar", "build-desconocida")
        self.assertEqual(entrada["estado_version"], ident.INDETERMINADO)

    def test_cve_sin_rangos_para_el_producto(self):
        # CVE real de WinRAR evaluado contra otro producto: sin rangos -> INDETERMINADO.
        item = cargar_fixture("cve_2023_40477.json")["vulnerabilities"][0]
        entrada = ident.analizar_cve(item, "rarlab", "unrar_inexistente", "6.00")
        self.assertEqual(entrada["versiones_afectadas"], [])
        self.assertEqual(entrada["estado_version"], ident.INDETERMINADO)

    def test_rango_sin_limites(self):
        self.assertIsNone(ident.version_en_rango(ident.Version("1.0"), ident._rango_vacio()))


class TestErroresNVD(unittest.TestCase):
    """(d) Error simulado de comunicación con la NVD."""

    def test_error_de_red_no_rompe_el_analisis(self):
        error = requests.exceptions.ConnectionError("sin conexión")
        sesion = SesionSecuencia([error] * (ident.MAX_REINTENTOS + 1))
        cliente = crear_cliente(sesion)
        programa = {"programa": "WinRAR", "nombre_original": "WinRAR", "version": "6.00"}
        resultado = ident.analizar_programa(cliente, programa)
        self.assertEqual(resultado["estado_identificacion"], ident.ERROR_NVD)
        self.assertEqual(resultado["estado_programa"], ident.INDETERMINADO)
        self.assertIn("Error de comunicación", resultado["nota"])
        self.assertEqual(sesion.llamadas, ident.MAX_REINTENTOS + 1)
        # Esperas exponenciales entre reintentos: 10, 20, 40.
        self.assertEqual([e for e in cliente.esperas if e >= ident.ESPERA_BASE_REINTENTO], [10, 20, 40])

    def test_reintento_tras_429(self):
        sesion = SesionSecuencia([RespuestaFalsa(429), RespuestaFalsa(200, cargar_fixture("cpe_winrar.json"))])
        cliente = crear_cliente(sesion)
        productos = cliente.buscar_cpe("winrar")
        self.assertTrue(productos)
        self.assertEqual(sesion.llamadas, 2)

    def test_http_400_no_se_reintenta(self):
        sesion = SesionSecuencia([RespuestaFalsa(400)])
        cliente = crear_cliente(sesion)
        with self.assertRaises(ident.ErrorNVD):
            cliente.buscar_cpe("winrar")
        self.assertEqual(sesion.llamadas, 1)

    def test_api_key_en_cabecera_y_pausa(self):
        sesion = SesionFixtures(MAPA_CPE, MAPA_CVE)
        cliente = crear_cliente(sesion, api_key="clave-de-prueba")
        cliente.buscar_cpe("winrar")
        self.assertEqual(sesion.peticiones[0]["headers"]["apiKey"], "clave-de-prueba")
        self.assertEqual(cliente.pausa, ident.PAUSA_CON_CLAVE)
        self.assertEqual(crear_cliente(sesion).pausa, ident.PAUSA_SIN_CLAVE)


class TestInformeCompleto(unittest.TestCase):
    """Genera vulnerabilidades.json en una carpeta temporal."""

    def test_vulnerabilidades_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            carpeta = Path(tmp)
            (carpeta / "equipo.json").write_text(
                json.dumps({"equipo": "DESKTOP-2N2J8P4", "ip": "192.168.1.38"}), encoding="utf-8"
            )
            software = [
                {"Name": "WinRAR versión 6.00", "Version": "6.00"},
                {"Name": "VLC media player", "Version": "3.0.24"},
                {"Name": "Configurador FNMT", "Version": "5.1.2"},
                {"Name": "Sin versión", "Version": None},
            ]
            (carpeta / "software.json").write_text(json.dumps(software, ensure_ascii=False), encoding="utf-8")

            cliente = crear_cliente(SesionFixtures(MAPA_CPE, MAPA_CVE))
            informe = ident.analizar_vulnerabilidades(carpeta, cliente=cliente)

            guardado = json.loads((carpeta / "vulnerabilidades.json").read_text(encoding="utf-8"))
            self.assertEqual(guardado["equipo"], "DESKTOP-2N2J8P4")
            self.assertEqual(guardado, json.loads(json.dumps(informe)))
            r = guardado["resumen"]
            self.assertEqual(r["total_programas_analizados"], 4)
            self.assertEqual(r["programas_con_version"], 3)
            self.assertEqual(r["programas_identificados_cpe"], 2)
            self.assertEqual(r["sin_coincidencia_cpe"], 1)
            self.assertEqual(r["programas_afectados"], 1)
            self.assertEqual(r["programas_no_afectados"], 1)  # VLC 3.0.24: 0 CVE analizados
            self.assertEqual(r["total_cve_encontrados"], 7)
            self.assertEqual(r["cve_afectados"], 7)
            self.assertFalse((carpeta / "vulnerabilidades.json.tmp").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
