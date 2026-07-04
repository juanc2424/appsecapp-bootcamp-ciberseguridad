import json
import pathlib
import time

import requests

from . import config, exodus_client, mobsf_client, parametros, vt_client


def analizar(ruta_apk: str) -> dict:
    """Orquesta MobSF + Exodus + VirusTotal sobre un APK y normaliza el resultado
    a un JSON común."""
    apk_path = pathlib.Path(ruta_apk).resolve()
    nombre_apk = apk_path.name

    mobsf_report = mobsf_client.analizar_apk(str(apk_path))

    try:
        exodus_report = exodus_client.analizar_apk(nombre_apk)
    except (FileNotFoundError, RuntimeError) as err:
        exodus_report = None
        exodus_error = str(err)
    else:
        exodus_error = None

    resumen_vt = None
    motivo_ausencia_vt = None
    if not config.VT_API_KEY:
        motivo_ausencia_vt = "VirusTotal no configurado (VT_API_KEY vacío en .env)."
    else:
        try:
            reporte_vt = vt_client.consultar_por_hash(mobsf_report["md5"])
        except requests.exceptions.RequestException as err:
            motivo_ausencia_vt = f"Error consultando VirusTotal: {err}"
        else:
            if reporte_vt is None:
                motivo_ausencia_vt = (
                    "El hash del APK no está en la base de VirusTotal "
                    "(nadie lo subió antes; no implica que sea seguro)."
                )
            else:
                resumen_vt = vt_client.resumen_deteccion(reporte_vt)

    reporte = {
        "app": {
            "package_name": mobsf_report.get("package_name"),
            "app_name": mobsf_report.get("app_name"),
            "version_name": mobsf_report.get("version_name"),
            "version_code": mobsf_report.get("version_code"),
            "md5": mobsf_report.get("md5"),
            "mobsf_security_score": mobsf_report.get("appsec", {}).get("security_score"),
        },
        "parametros": parametros.extraer_todos(
            mobsf_report, exodus_report, resumen_vt, motivo_ausencia_vt
        ),
        "meta": {
            "generado": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "exodus_error": exodus_error,
        },
    }

    salida = config.RESULTADOS_DIR / f"{apk_path.stem}.json"
    with open(salida, "w") as f:
        json.dump(reporte, f, indent=2, ensure_ascii=False)

    reporte["meta"]["archivo_salida"] = str(salida)
    return reporte
