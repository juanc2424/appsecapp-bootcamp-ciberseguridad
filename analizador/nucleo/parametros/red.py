from ..modelos import ContextoAnalisis, ValorParametro
from .base import ExtractorParametro


class CifradoTransitoInseguro(ExtractorParametro):
    """MASVS-NETWORK: cleartext permitido, TLS mal configurado, etc."""

    nombre = "cifrado_transito_inseguro"

    def extraer(self, ctx: ContextoAnalisis) -> ValorParametro:
        hallazgos = [
            h
            for h in ctx.mobsf.get("network_security", {}).get("network_findings", [])
            if h.get("severity") in ("high", "warning")
        ]
        return ValorParametro(len(hallazgos) > 0, hallazgos)
