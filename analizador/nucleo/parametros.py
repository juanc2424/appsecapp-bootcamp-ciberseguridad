"""Extrae los 10 parámetros de `criterios_evaluacion_seguridad_apps.md` (§5)
a partir de los reportes crudos de MobSF y exodus-standalone, más "CVE en
SDKs" (fila 9 de la matriz Parámetro→Seguridad en `hoja_de_ruta_proyecto.md`
§3), cruzando los trackers/SDKs ya identificados contra OSV.dev.

Los parámetros de minimización de datos, declaración vs. realidad y
procedencia/reputación no son evaluables solo con análisis estático; quedan
marcados como pendientes para revisión manual / Fase 4 (VirusTotal opcional).
"""

import requests

from . import osv_client

# Coordenadas Maven conocidas para los SDKs de terceros más comunes que
# aparecen como trackers. No es exhaustivo: la mayoría de SDKs de
# anuncios/analítica son propietarios y no publican artefactos en Maven
# Central, así que no tendrán coincidencia (limitación real, documentada en
# el informe en vez de intentar adivinar coordenadas).
SDKS_CONOCIDOS = {
    "AppsFlyer": "com.appsflyer:af-android-sdk",
    "Google Firebase Analytics": "com.google.firebase:firebase-analytics",
    "Google Analytics": "com.google.android.gms:play-services-analytics",
    "Google AdMob": "com.google.android.gms:play-services-ads",
    "Facebook Ads": "com.facebook.android:audience-network-sdk",
    "Unity3d Ads": "com.unity3d.ads:unity-ads",
    "Twitter MoPub": "com.mopub:mopub-sdk",
    "Flurry": "com.flurry.android:analytics",
    "ACRA": "ch.acra:acra-core",
}

PERMISOS_SENSIBLES = {
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.BODY_SENSORS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.READ_PHONE_STATE",
}


def permisos_peligrosos(mobsf_report: dict) -> dict:
    peligrosos = [
        nombre
        for nombre, info in mobsf_report.get("permissions", {}).items()
        if info.get("status") == "dangerous"
    ]
    return {"valor": len(peligrosos), "detalle": peligrosos}


def sobre_privilegio(mobsf_report: dict) -> dict:
    permisos = mobsf_report.get("permissions", {})
    total = len(permisos)
    peligrosos = sum(1 for info in permisos.values() if info.get("status") == "dangerous")
    ratio = round(peligrosos / total, 2) if total else 0.0
    return {
        "valor": ratio,
        "detalle": f"{peligrosos}/{total} permisos declarados son 'dangerous' "
        "(proxy estático; no compara contra la función real de la app)",
    }


def combinacion_sensible_internet(mobsf_report: dict) -> dict:
    permisos = set(mobsf_report.get("permissions", {}).keys())
    tiene_internet = "android.permission.INTERNET" in permisos
    sensibles_presentes = sorted(permisos & PERMISOS_SENSIBLES)
    return {
        "valor": bool(tiene_internet and sensibles_presentes),
        "detalle": {
            "tiene_internet": tiene_internet,
            "permisos_sensibles_presentes": sensibles_presentes,
        },
    }


def trackers(exodus_report: dict | None, mobsf_report: dict) -> dict:
    encontrados = {}
    if exodus_report:
        for t in exodus_report.get("trackers", []):
            encontrados[t["name"]] = {"id": t.get("id"), "fuente": "exodus"}
    for t in mobsf_report.get("trackers", {}).get("trackers", []):
        encontrados.setdefault(t["name"], {"categorias": t.get("categories"), "fuente": "mobsf"})
    return {"valor": len(encontrados), "detalle": encontrados}


def cifrado_transito(mobsf_report: dict) -> dict:
    hallazgos = [
        h
        for h in mobsf_report.get("network_security", {}).get("network_findings", [])
        if h.get("severity") in ("high", "warning")
    ]
    return {"valor": len(hallazgos) > 0, "detalle": hallazgos}


def almacenamiento_inseguro(mobsf_report: dict) -> dict:
    findings = mobsf_report.get("code_analysis", {}).get("findings", {})
    hallazgos = [
        {"regla": regla, **info.get("metadata", {})}
        for regla, info in findings.items()
        if info.get("metadata", {}).get("masvs", "").startswith("MSTG-STORAGE")
    ]
    return {"valor": len(hallazgos), "detalle": hallazgos}


def config_inseguras(mobsf_report: dict) -> dict:
    hallazgos = mobsf_report.get("manifest_analysis", {}).get("manifest_findings", [])
    exportados = [h for h in hallazgos if "exported" in h.get("rule", "")]
    backup = any(h.get("rule") == "app_allowbackup" for h in hallazgos)
    debuggable = any("debuggable" in h.get("rule", "") for h in hallazgos)
    return {
        "valor": len(exportados) + int(backup) + int(debuggable),
        "detalle": {
            "componentes_exportados_sin_proteger": len(exportados),
            "allow_backup": backup,
            "debuggable": debuggable,
        },
    }


def minimizacion_datos() -> dict:
    return {
        "valor": None,
        "detalle": "No evaluable con análisis estático: requiere probar la app "
        "negando cada permiso (Fase 4, manual).",
    }


def declaracion_vs_realidad() -> dict:
    return {
        "valor": None,
        "detalle": "Pendiente: requiere comparar la etiqueta 'Seguridad de los "
        "datos' de Google Play contra los hallazgos automáticos (Fase 4, manual).",
    }


def cve_en_sdks(trackers_detectados: dict) -> dict:
    coincidencias = {}
    sin_mapeo = []
    for nombre in trackers_detectados:
        coordenada = SDKS_CONOCIDOS.get(nombre)
        if not coordenada:
            sin_mapeo.append(nombre)
            continue
        try:
            vulns = osv_client.buscar(coordenada)
        except requests.exceptions.RequestException as err:
            coincidencias[nombre] = {"error": str(err)}
            continue
        if vulns:
            coincidencias[nombre] = {
                "paquete": coordenada,
                "cves": [v["id"] for v in vulns],
            }
    return {
        "valor": sum(len(v.get("cves", [])) for v in coincidencias.values()),
        "detalle": {
            "sdks_con_cve": coincidencias,
            "sdks_sin_coordenada_maven_conocida": sin_mapeo,
        },
    }


def procedencia_reputacion(resumen_vt: dict | None, motivo_ausencia: str | None = None) -> dict:
    if resumen_vt is None:
        return {
            "valor": None,
            "detalle": motivo_ausencia or "VirusTotal no disponible para este APK.",
        }
    return {"valor": resumen_vt["maliciosos"] + resumen_vt["sospechosos"], "detalle": resumen_vt}


def extraer_todos(
    mobsf_report: dict,
    exodus_report: dict | None,
    resumen_vt: dict | None = None,
    motivo_ausencia_vt: str | None = None,
) -> dict:
    trackers_detectados = trackers(exodus_report, mobsf_report)
    return {
        "permisos_peligrosos": permisos_peligrosos(mobsf_report),
        "sobre_privilegio": sobre_privilegio(mobsf_report),
        "permiso_sensible_mas_internet": combinacion_sensible_internet(mobsf_report),
        "trackers": trackers_detectados,
        "minimizacion_datos": minimizacion_datos(),
        "cifrado_transito_inseguro": cifrado_transito(mobsf_report),
        "almacenamiento_inseguro": almacenamiento_inseguro(mobsf_report),
        "config_inseguras": config_inseguras(mobsf_report),
        "cve_en_sdks": cve_en_sdks(trackers_detectados["detalle"]),
        "declaracion_vs_realidad": declaracion_vs_realidad(),
        "procedencia_reputacion": procedencia_reputacion(resumen_vt, motivo_ausencia_vt),
    }
