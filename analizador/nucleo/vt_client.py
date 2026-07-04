import requests

from . import config

_BASE = "https://www.virustotal.com/api/v3"


def _headers():
    return {"x-apikey": config.VT_API_KEY}


def consultar_por_hash(hash_apk: str) -> dict | None:
    """Reputación de un archivo ya conocido por VirusTotal (por MD5/SHA256).

    Devuelve None si el hash no está en su base (no implica que el archivo
    sea seguro, solo que nadie lo subió antes)."""
    resp = requests.get(f"{_BASE}/files/{hash_apk}", headers=_headers(), timeout=30)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


def resumen_deteccion(reporte_vt: dict) -> dict:
    attrs = reporte_vt["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    return {
        "maliciosos": stats.get("malicious", 0),
        "sospechosos": stats.get("suspicious", 0),
        "total_motores": sum(stats.values()) if stats else 0,
        "reputacion": attrs.get("reputation"),
    }
