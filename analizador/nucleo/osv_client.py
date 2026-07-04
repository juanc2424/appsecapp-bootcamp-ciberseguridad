import requests

_ENDPOINT = "https://api.osv.dev/v1/query"


def buscar(paquete: str, ecosistema: str = "Maven") -> list[dict]:
    """Consulta OSV.dev por vulnerabilidades conocidas de un paquete (sin versión:
    devuelve el historial completo, no filtrado a una versión instalada)."""
    resp = requests.post(
        _ENDPOINT,
        json={"package": {"name": paquete, "ecosystem": ecosistema}},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json().get("vulns", [])
