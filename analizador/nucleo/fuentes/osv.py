import requests

from .base import FuenteVulnerabilidades


class ClienteOSV(FuenteVulnerabilidades):
    """Consulta OSV.dev por vulnerabilidades conocidas de un paquete."""

    _ENDPOINT = "https://api.osv.dev/v1/query"

    def __init__(self, ecosistema: str = "Maven"):
        self._ecosistema = ecosistema

    def vulnerabilidades(self, paquete: str) -> list[dict]:
        """Sin versión: devuelve el historial completo del paquete, no
        filtrado a la versión embebida en el APK."""
        resp = requests.post(
            self._ENDPOINT,
            json={"package": {"name": paquete, "ecosystem": self._ecosistema}},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json().get("vulns", [])
