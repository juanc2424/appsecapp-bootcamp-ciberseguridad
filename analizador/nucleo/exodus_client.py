import json
import subprocess

from . import config


def analizar_apk(nombre_apk: str) -> dict:
    """Corre exodus-standalone (contenedor Docker) sobre un APK en apks/.

    exodus_analyze.py usa su código de salida para contar trackers (no 0 =
    error), así que el éxito se valida por la existencia del JSON de salida,
    no por el returncode del proceso.
    """
    apk_path = config.APKS_DIR / nombre_apk
    if not apk_path.exists():
        raise FileNotFoundError(f"No existe {apk_path}; el APK debe estar en apks/")

    salida = f"exodus_{apk_path.stem}.json"
    salida_path = config.RESULTADOS_DIR / salida

    proceso = subprocess.run(
        [
            "docker", "compose", "run", "--rm", "exodus",
            f"/apks/{nombre_apk}", "-j", "-o", f"/resultados/{salida}",
        ],
        cwd=config.PROYECTO_DIR,
        capture_output=True,
        text=True,
    )

    if not salida_path.exists():
        raise RuntimeError(
            f"exodus-standalone no generó reporte para {nombre_apk}.\n"
            f"stdout: {proceso.stdout}\nstderr: {proceso.stderr}"
        )

    with open(salida_path) as f:
        return json.load(f)
