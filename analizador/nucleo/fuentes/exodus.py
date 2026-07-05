import json
from pathlib import Path

from . import docker_compose
from .base import FuenteReporteApk


class ClienteExodus(FuenteReporteApk):
    """Corre exodus-standalone (contenedor Docker) sobre un APK en apks/."""

    def __init__(self, proyecto_dir: Path, apks_dir: Path, resultados_dir: Path):
        self._proyecto_dir = proyecto_dir
        self._apks_dir = apks_dir
        self._resultados_dir = resultados_dir

    def analizar(self, ruta_apk: Path) -> dict:
        """exodus_analyze.py usa su código de salida para contar trackers
        (no 0 = error), así que el éxito se valida por la existencia del
        JSON de salida, no por el returncode del proceso."""
        nombre = ruta_apk.name
        if not (self._apks_dir / nombre).exists():
            raise FileNotFoundError(
                f"No existe {self._apks_dir / nombre}; el APK debe estar en apks/"
            )

        salida = f"exodus_{ruta_apk.stem}.json"
        salida_path = self._resultados_dir / salida
        # Un JSON viejo de una corrida anterior haría pasar por éxito un fallo.
        salida_path.unlink(missing_ok=True)

        proceso = docker_compose.correr(
            [
                "run", "--rm", "exodus",
                f"/apks/{nombre}", "-j", "-o", f"/resultados/{salida}",
            ],
            cwd=self._proyecto_dir,
            capture_output=True,
            text=True,
        )

        if not salida_path.exists():
            raise RuntimeError(
                f"exodus-standalone no generó reporte para {nombre}.\n"
                f"stdout: {proceso.stdout}\nstderr: {proceso.stderr}"
            )

        with open(salida_path) as f:
            return json.load(f)
