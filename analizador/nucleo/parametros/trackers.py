from ..modelos import ContextoAnalisis, ValorParametro
from .base import ExtractorParametro


def combinar_trackers(ctx: ContextoAnalisis) -> dict:
    """Une los trackers vistos por Exodus y MobSF (Exodus tiene prioridad).
    También lo usa CveEnSdks para saber qué SDKs cruzar contra OSV."""
    encontrados = {}
    if ctx.exodus:
        for t in ctx.exodus.get("trackers", []):
            encontrados[t["name"]] = {"id": t.get("id"), "fuente": "exodus"}
    for t in ctx.mobsf.get("trackers", {}).get("trackers", []):
        encontrados.setdefault(t["name"], {"categorias": t.get("categories"), "fuente": "mobsf"})
    return encontrados


class Trackers(ExtractorParametro):
    nombre = "trackers"

    def extraer(self, ctx: ContextoAnalisis) -> ValorParametro:
        encontrados = combinar_trackers(ctx)
        return ValorParametro(len(encontrados), encontrados)
