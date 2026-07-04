import requests

from ..fuentes.base import FuenteReputacion
from ..modelos import ContextoAnalisis, ValorParametro
from .base import ExtractorParametro


class ProcedenciaReputacion(ExtractorParametro):
    """Vetting NIST 800-163: reputación del binario en listas de malware."""

    nombre = "procedencia_reputacion"

    def __init__(self, fuente: FuenteReputacion | None):
        self._fuente = fuente

    def extraer(self, ctx: ContextoAnalisis) -> ValorParametro:
        if self._fuente is None:
            return ValorParametro(
                None, "VirusTotal no configurado (VT_API_KEY vacío en .env)."
            )
        try:
            resumen = self._fuente.consultar(ctx.md5)
        except requests.exceptions.RequestException as err:
            return ValorParametro(None, f"Error consultando VirusTotal: {err}")
        if resumen is None:
            return ValorParametro(
                None,
                "El hash del APK no está en la base de VirusTotal "
                "(nadie lo subió antes; no implica que sea seguro).",
            )
        return ValorParametro(resumen["maliciosos"] + resumen["sospechosos"], resumen)
