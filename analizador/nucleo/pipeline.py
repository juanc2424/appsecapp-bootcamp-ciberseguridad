import pathlib
import time

from .fuentes.base import FuenteReporteApk
from .modelos import ContextoAnalisis
from .parametros.base import ExtractorParametro
from .persistencia import RepositorioResultados
from .puntaje import CalculadoraRiesgo


class Orquestador:
    """Corre las fuentes sobre un APK, extrae los parámetros y guarda el reporte.

    Depende solo de abstracciones (fuentes, extractores y calculadora
    inyectados): agregar una herramienta o un parámetro nuevo no requiere
    tocar esta clase.
    """

    def __init__(
        self,
        analisis_estatico: FuenteReporteApk,
        trackers: FuenteReporteApk,
        extractores: list[ExtractorParametro],
        repositorio: RepositorioResultados,
        calculadora: CalculadoraRiesgo | None = None,
    ):
        self._analisis_estatico = analisis_estatico
        self._trackers = trackers
        self._extractores = extractores
        self._repositorio = repositorio
        self._calculadora = calculadora

    def analizar(self, ruta_apk: str) -> dict:
        apk_path = pathlib.Path(ruta_apk).resolve()

        mobsf_report = self._analisis_estatico.analizar(apk_path)

        try:
            exodus_report = self._trackers.analizar(apk_path)
        except (FileNotFoundError, RuntimeError) as err:
            exodus_report, exodus_error = None, str(err)
        else:
            exodus_error = None

        ctx = ContextoAnalisis(
            mobsf=mobsf_report, exodus=exodus_report, exodus_error=exodus_error
        )

        reporte = {
            "app": {
                "package_name": mobsf_report.get("package_name"),
                "app_name": mobsf_report.get("app_name"),
                "version_name": mobsf_report.get("version_name"),
                "version_code": mobsf_report.get("version_code"),
                "md5": mobsf_report.get("md5"),
                "mobsf_security_score": mobsf_report.get("appsec", {}).get("security_score"),
            },
            "parametros": {e.nombre: e.extraer(ctx).a_dict() for e in self._extractores},
            "meta": {
                "generado": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "exodus_error": exodus_error,
            },
        }
        if self._calculadora is not None:
            reporte["puntaje"] = self._calculadora.calcular(reporte["parametros"])

        salida = self._repositorio.guardar(reporte, apk_path.stem)
        reporte["meta"]["archivo_salida"] = str(salida)
        return reporte
