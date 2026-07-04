import requests

from ..fuentes.base import FuenteVulnerabilidades
from ..modelos import ContextoAnalisis, ValorParametro
from .base import ExtractorParametro
from .trackers import combinar_trackers

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


class CveEnSdks(ExtractorParametro):
    """M2 Supply Chain: cruza los SDKs/trackers detectados contra la base
    de vulnerabilidades (OSV.dev)."""

    nombre = "cve_en_sdks"

    def __init__(self, fuente: FuenteVulnerabilidades):
        self._fuente = fuente

    def extraer(self, ctx: ContextoAnalisis) -> ValorParametro:
        coincidencias = {}
        sin_mapeo = []
        for nombre_sdk in combinar_trackers(ctx):
            coordenada = SDKS_CONOCIDOS.get(nombre_sdk)
            if not coordenada:
                sin_mapeo.append(nombre_sdk)
                continue
            try:
                vulns = self._fuente.vulnerabilidades(coordenada)
            except requests.exceptions.RequestException as err:
                coincidencias[nombre_sdk] = {"error": str(err)}
                continue
            if vulns:
                coincidencias[nombre_sdk] = {
                    "paquete": coordenada,
                    "cves": [v["id"] for v in vulns],
                }
        return ValorParametro(
            sum(len(v.get("cves", [])) for v in coincidencias.values()),
            {
                "sdks_con_cve": coincidencias,
                "sdks_sin_coordenada_maven_conocida": sin_mapeo,
            },
        )
