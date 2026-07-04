import requests

from . import config

_TIMEOUT = 300
# El análisis estático completo (/api/v1/scan) puede tardar bastante en APKs
# grandes/ofuscadas; se le da más margen que al resto de llamadas REST.
_TIMEOUT_SCAN = 1800


def _headers():
    return {"Authorization": config.MOBSF_API_KEY}


def esta_disponible() -> bool:
    """Verifica que la instancia de MobSF (Docker) responda."""
    try:
        resp = requests.get(config.MOBSF_URL, timeout=5)
        return resp.status_code == 200
    except requests.exceptions.RequestException:
        return False


def subir_apk(ruta_apk: str) -> str:
    """Sube el APK a MobSF y devuelve su hash (identificador del scan)."""
    with open(ruta_apk, "rb") as f:
        resp = requests.post(
            f"{config.MOBSF_URL}/api/v1/upload",
            files={"file": (ruta_apk.split("/")[-1], f, "application/octet-stream")},
            headers=_headers(),
            timeout=_TIMEOUT,
        )
    resp.raise_for_status()
    return resp.json()["hash"]


def escanear(hash_apk: str) -> dict:
    """Dispara el análisis estático sobre un APK ya subido."""
    resp = requests.post(
        f"{config.MOBSF_URL}/api/v1/scan",
        data={"hash": hash_apk},
        headers=_headers(),
        timeout=_TIMEOUT_SCAN,
    )
    resp.raise_for_status()
    return resp.json()


def reporte_json(hash_apk: str) -> dict:
    """Obtiene el reporte completo (permisos, storage, network, config) en JSON."""
    resp = requests.post(
        f"{config.MOBSF_URL}/api/v1/report_json",
        data={"hash": hash_apk},
        headers=_headers(),
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def analizar_apk(ruta_apk: str) -> dict:
    """Pipeline completo: subir → escanear → reporte_json."""
    hash_apk = subir_apk(ruta_apk)
    escanear(hash_apk)
    return reporte_json(hash_apk)
