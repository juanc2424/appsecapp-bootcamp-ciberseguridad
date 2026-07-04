import requests

from .base import FuenteReputacion


class ClienteVirusTotal(FuenteReputacion):
    """Reputación de un archivo por hash contra VirusTotal (API v3)."""

    _BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self._api_key = api_key

    def consultar(self, hash_archivo: str) -> dict | None:
        resp = requests.get(
            f"{self._BASE}/files/{hash_archivo}",
            headers={"x-apikey": self._api_key},
            timeout=30,
        )
        if resp.status_code == 404:
            # Nadie subió este archivo antes; no implica que sea seguro.
            return None
        resp.raise_for_status()
        attrs = resp.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        return {
            "maliciosos": stats.get("malicious", 0),
            "sospechosos": stats.get("suspicious", 0),
            "total_motores": sum(stats.values()) if stats else 0,
            "reputacion": attrs.get("reputation"),
        }
