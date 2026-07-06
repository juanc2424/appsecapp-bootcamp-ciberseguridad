import time
from pathlib import Path

import requests

from .base import FuenteReporteApk, Verificable


class ClienteMobSF(FuenteReporteApk, Verificable):
    """Habla con la instancia de MobSF (Docker) por su REST API.

    Las apps grandes/ofuscadas hacen que un scan tarde mucho y sature a MobSF;
    mientras termina, las peticiones siguientes reciben RemoteDisconnected o
    timeout. Por eso las llamadas se reintentan con backoff y se espera a que
    MobSF vuelva a responder antes de reintentar (así una app pesada no
    "envenena" a las que le siguen en el lote). MobSF cachea el scan por hash,
    así que reintentar tras un timeout suele resolver rápido con el resultado
    ya calculado.
    """

    _TIMEOUT = 300
    _TIMEOUT_SCAN = 1800
    _REINTENTOS = 3
    _BACKOFF_BASE = 20  # segundos: 20, 40, 80…

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

    def esperar_disponible(self, intentos: int = 30, espera: int = 10) -> bool:
        """Sondea hasta que MobSF vuelva a responder (tras un scan pesado)."""
        for _ in range(intentos):
            if self.esta_disponible():
                return True
            time.sleep(espera)
        return False

    def _pedir(self, metodo: str, ruta: str, timeout: int, **kwargs) -> dict:
        """Hace la petición reintentando ante caídas de conexión/timeout, que
        con MobSF suelen ser 'está ocupado', no 'falló para siempre'."""
        ultimo_error = None
        for intento in range(self._REINTENTOS):
            try:
                resp = requests.request(
                    metodo, f"{self._url}{ruta}", headers=self._headers(),
                    timeout=timeout, **kwargs
                )
                resp.raise_for_status()
                return resp.json()
            except (
                requests.exceptions.ConnectionError,      # incluye RemoteDisconnected
                requests.exceptions.ChunkedEncodingError,
                requests.exceptions.ReadTimeout,
            ) as err:
                ultimo_error = err
                # MobSF sigue procesando del lado servidor: esperar a que se
                # libere y reintentar (el scan queda cacheado por hash).
                self.esperar_disponible()
                if intento < self._REINTENTOS - 1:
                    time.sleep(self._BACKOFF_BASE * (2 ** intento))
        raise ultimo_error

    def subir(self, ruta_apk: Path) -> str:
        """Sube el APK a MobSF y devuelve su hash (identificador del scan)."""
        # Se leen los bytes una vez (no un file handle) para que _pedir pueda
        # reintentar el POST sin que el archivo quede consumido tras el 1er intento.
        contenido = ruta_apk.read_bytes()
        datos = self._pedir(
            "POST", "/api/v1/upload", self._TIMEOUT,
            files={"file": (ruta_apk.name, contenido, "application/octet-stream")},
        )
        return datos["hash"]

    def escanear(self, hash_apk: str) -> dict:
        """Dispara el análisis estático sobre un APK ya subido."""
        return self._pedir("POST", "/api/v1/scan", self._TIMEOUT_SCAN, data={"hash": hash_apk})

    def reporte_json(self, hash_apk: str) -> dict:
        """Obtiene el reporte completo (permisos, storage, network, config)."""
        return self._pedir("POST", "/api/v1/report_json", self._TIMEOUT, data={"hash": hash_apk})

    def analizar(self, ruta_apk: Path) -> dict:
        """Pipeline completo: subir → escanear → reporte_json."""
        hash_apk = self.subir(ruta_apk)
        self.escanear(hash_apk)
        return self.reporte_json(hash_apk)
