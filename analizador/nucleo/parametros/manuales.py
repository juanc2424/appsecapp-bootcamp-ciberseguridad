"""Parámetros que no son evaluables con análisis estático; quedan marcados
como pendientes de revisión manual (Fase 4)."""

from ..modelos import ContextoAnalisis, ValorParametro
from .base import ExtractorParametro


class MinimizacionDatos(ExtractorParametro):
    nombre = "minimizacion_datos"

    def extraer(self, ctx: ContextoAnalisis) -> ValorParametro:
        return ValorParametro(
            None,
            "No evaluable con análisis estático: requiere probar la app "
            "negando cada permiso (Fase 4, manual).",
        )


class DeclaracionVsRealidad(ExtractorParametro):
    nombre = "declaracion_vs_realidad"

    def extraer(self, ctx: ContextoAnalisis) -> ValorParametro:
        return ValorParametro(
            None,
            "Pendiente: requiere comparar la etiqueta 'Seguridad de los "
            "datos' de Google Play contra los hallazgos automáticos (Fase 4, manual).",
        )
