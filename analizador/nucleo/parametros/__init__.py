from ..fuentes.base import FuenteReputacion, FuenteVulnerabilidades
from .almacenamiento import AlmacenamientoInseguro
from .base import ExtractorParametro
from .cadena_suministro import CveEnSdks
from .configuracion import ConfigInseguras
from .manuales import DeclaracionVsRealidad, MinimizacionDatos
from .permisos import CombinacionSensibleInternet, PermisosPeligrosos, SobrePrivilegio
from .red import CifradoTransitoInseguro
from .reputacion import ProcedenciaReputacion
from .trackers import Trackers


def extractores_por_defecto(
    vulnerabilidades: FuenteVulnerabilidades,
    reputacion: FuenteReputacion | None,
) -> list[ExtractorParametro]:
    """Los parámetros de la matriz Parámetro→Seguridad, en el orden del reporte."""
    return [
        PermisosPeligrosos(),
        SobrePrivilegio(),
        CombinacionSensibleInternet(),
        Trackers(),
        MinimizacionDatos(),
        CifradoTransitoInseguro(),
        AlmacenamientoInseguro(),
        ConfigInseguras(),
        CveEnSdks(vulnerabilidades),
        DeclaracionVsRealidad(),
        ProcedenciaReputacion(reputacion),
    ]
