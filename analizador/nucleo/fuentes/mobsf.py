from pathlib import Path

import requests

from .base import FuenteReporteApk, Verificable


class ClienteMobSF(FuenteReporteApk, Verificable):
    """Habla con la instancia de MobSF (Docker) por su REST API."""

    _TIMEOUT = 300
    # El análisis estático completo (/api/v1/scan) puede tardar bastante en
    # APKs grandes/ofuscadas; se le da más margen que al resto de llamadas.
    _TIMEOUT_SCAN = 1800

    def __init__(self, url: str, api_key: str):
        self._url = url
        self._api_key = api_key

    def _headers(self) -> dict:
        return {"Authorization": self._api_key}

    def esta_disponible(self) -> bool:
        try:
            resp = requests.get(self._url, timeout=5)
            return resp.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def subir(self, ruta_apk: Path) -> str:
        """Sube el APK a MobSF y devuelve su hash (identificador del scan)."""
        with open(ruta_apk, "rb") as f:
            resp = requests.post(
                f"{self._url}/api/v1/upload",
                files={"file": (ruta_apk.name, f, "application/octet-stream")},
                headers=self._headers(),
                timeout=self._TIMEOUT,
            )
        resp.raise_for_status()
        return resp.json()["hash"]

    def escanear(self, hash_apk: str) -> dict:
        """Dispara el análisis estático sobre un APK ya subido."""
        resp = requests.post(
            f"{self._url}/api/v1/scan",
            data={"hash": hash_apk},
            headers=self._headers(),
            timeout=self._TIMEOUT_SCAN,
        )
        resp.raise_for_status()
        return resp.json()

    def reporte_json(self, hash_apk: str) -> dict:
        """Obtiene el reporte completo (permisos, storage, network, config)."""
        resp = requests.post(
            f"{self._url}/api/v1/report_json",
            data={"hash": hash_apk},
            headers=self._headers(),
            timeout=self._TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()

    def analizar(self, ruta_apk: Path) -> dict:
        """Pipeline completo: subir → escanear → reporte_json."""
        hash_apk = self.subir(ruta_apk)
        self.escanear(hash_apk)
        return self.reporte_json(hash_apk)
