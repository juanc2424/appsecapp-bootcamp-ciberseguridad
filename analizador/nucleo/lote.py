"""Análisis por lote del dataset de calibración y consolidación de resultados.

Reutiliza el mismo Orquestador y Descargador que el análisis individual; su
única responsabilidad extra es iterar, ser reanudable (saltar lo ya hecho),
tolerar fallos por app y volcar un resumen tabular para el scoring.
"""

import csv
import json
from pathlib import Path
from typing import Callable

from .fuentes.base import DescargadorApk
from .pipeline import Orquestador
from .puntaje import CalculadoraRiesgo


def leer_packages(archivo: Path) -> list[str]:
    """Un package por línea; ignora comentarios (#) y líneas vacías."""
    packages = []
    for linea in archivo.read_text().splitlines():
        linea = linea.split("#", 1)[0].strip()
        if linea:
            packages.append(linea)
    return packages


def _ya_analizado(package: str, resultados_dir: Path) -> bool:
    return (resultados_dir / f"{package}.json").exists()


def analizar_lote(
    descargador: DescargadorApk,
    orquestador: Orquestador,
    packages: list[str],
    resultados_dir: Path,
    log: Callable[[str], None] = print,
) -> list[dict]:
    """Descarga + analiza cada package; salta los ya hechos y no se detiene
    ante un fallo individual. Devuelve el estado de cada uno."""
    estados = []
    total = len(packages)
    for i, package in enumerate(packages, 1):
        if _ya_analizado(package, resultados_dir):
            log(f"[{i}/{total}] {package} — ya analizado, se salta.")
            estados.append({"package": package, "estado": "saltado"})
            continue

        log(f"[{i}/{total}] {package} — descargando…")
        try:
            apk = descargador.descargar(package)
        except Exception as err:  # noqa: BLE001 — un fallo no debe frenar el lote
            log(f"[{i}/{total}] {package} — FALLO al descargar: {err}")
            estados.append({"package": package, "estado": "fallo_descarga", "error": str(err)})
            continue

        log(f"[{i}/{total}] {package} — analizando…")
        try:
            orquestador.analizar(str(apk))
        except Exception as err:  # noqa: BLE001
            log(f"[{i}/{total}] {package} — FALLO al analizar: {err}")
            estados.append({"package": package, "estado": "fallo_analisis", "error": str(err)})
            continue

        log(f"[{i}/{total}] {package} — OK.")
        estados.append({"package": package, "estado": "ok"})
    return estados


def _fila_resumen(reporte: dict, calculadora: CalculadoraRiesgo | None) -> dict:
    p = reporte["parametros"]
    vt = p["procedencia_reputacion"]["detalle"]
    vt = vt if isinstance(vt, dict) else {}
    # Reportes generados antes de existir el scoring no traen "puntaje";
    # se calcula al consolidar para que el CSV siempre lo tenga.
    puntaje = reporte.get("puntaje")
    if puntaje is None and calculadora is not None:
        puntaje = calculadora.calcular(p)
    puntaje = puntaje or {}
    return {
        "package": reporte["app"].get("package_name"),
        "app": reporte["app"].get("app_name"),
        "score": puntaje.get("total"),
        "semaforo": puntaje.get("semaforo"),
        "mobsf_score": reporte["app"].get("mobsf_security_score"),
        "permisos_peligrosos": p["permisos_peligrosos"]["valor"],
        "sobre_privilegio": p["sobre_privilegio"]["valor"],
        "sensible_mas_internet": p["permiso_sensible_mas_internet"]["valor"],
        "trackers": p["trackers"]["valor"],
        "cifrado_inseguro": p["cifrado_transito_inseguro"]["valor"],
        "almacenamiento_inseguro": p["almacenamiento_inseguro"]["valor"],
        "config_inseguras": p["config_inseguras"]["valor"],
        "cve_en_sdks": p["cve_en_sdks"]["valor"],
        "vt_maliciosos": vt.get("maliciosos"),
        "vt_reputacion": vt.get("reputacion"),
        "exodus_error": bool(reporte["meta"].get("exodus_error")),
    }


def consolidar(
    resultados_dir: Path, salida_csv: Path,
    calculadora: CalculadoraRiesgo | None = None,
) -> list[dict]:
    """Junta todos los reportes de app en una tabla plana (una fila por app)
    con score, semáforo y los parámetros numéricos."""
    filas = []
    for archivo in sorted(resultados_dir.glob("*.json")):
        if archivo.name.startswith("exodus_"):
            continue
        with open(archivo) as f:
            reporte = json.load(f)
        if "parametros" not in reporte:
            continue
        filas.append(_fila_resumen(reporte, calculadora))
    filas.sort(key=lambda f: f["score"] or 0, reverse=True)

    if filas:
        with open(salida_csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(filas[0].keys()))
            writer.writeheader()
            writer.writerows(filas)
    return filas
