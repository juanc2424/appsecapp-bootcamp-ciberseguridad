from ..modelos import ContextoAnalisis, ValorParametro
from .base import ExtractorParametro


class ConfigInseguras(ExtractorParametro):
    """MASVS-CODE: componentes exportados sin proteger, backup, debuggable."""

    nombre = "config_inseguras"

    def extraer(self, ctx: ContextoAnalisis) -> ValorParametro:
        hallazgos = ctx.mobsf.get("manifest_analysis", {}).get("manifest_findings", [])
        exportados = [h for h in hallazgos if "exported" in h.get("rule", "")]
        backup = any(h.get("rule") == "app_allowbackup" for h in hallazgos)
        debuggable = any("debuggable" in h.get("rule", "") for h in hallazgos)
        return ValorParametro(
            len(exportados) + int(backup) + int(debuggable),
            {
                "componentes_exportados_sin_proteger": len(exportados),
                "allow_backup": backup,
                "debuggable": debuggable,
            },
        )
