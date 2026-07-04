from ..modelos import ContextoAnalisis, ValorParametro
from .base import ExtractorParametro


class AlmacenamientoInseguro(ExtractorParametro):
    """MASVS-STORAGE: hallazgos de code_analysis etiquetados MSTG-STORAGE-*."""

    nombre = "almacenamiento_inseguro"

    def extraer(self, ctx: ContextoAnalisis) -> ValorParametro:
        findings = ctx.mobsf.get("code_analysis", {}).get("findings", {})
        hallazgos = [
            {"regla": regla, **info.get("metadata", {})}
            for regla, info in findings.items()
            if info.get("metadata", {}).get("masvs", "").startswith("MSTG-STORAGE")
        ]
        return ValorParametro(len(hallazgos), hallazgos)
