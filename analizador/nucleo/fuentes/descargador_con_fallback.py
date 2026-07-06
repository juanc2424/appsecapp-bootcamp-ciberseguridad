from pathlib import Path

from .base import DescargadorApk


class DescargadorConFallback(DescargadorApk):
    """Encadena varios DescargadorApk y usa el primero que consiga el APK.

    Ninguna fuente única mirrorea todo el catálogo de Google Play (bancos y
    apps de seguridad piden su remoción de mirrors como APKPure; otras apps
    simplemente no están indexadas). Encadenar fuentes evita que una clase
    tenga que conocer o distinguir entre ellas (abierto/cerrado): agregar una
    fuente nueva es agregar un descargador más a la lista, no tocar código
    existente."""

    def __init__(self, descargadores: list[DescargadorApk]):
        self._descargadores = descargadores

    def descargar(self, package: str) -> Path:
        errores = []
        for descargador in self._descargadores:
            try:
                return descargador.descargar(package)
            except Exception as err:  # noqa: BLE001 — se prueba la siguiente fuente
                errores.append(str(err))

        detalle = "\n---\n".join(errores)
        raise RuntimeError(f"Ninguna fuente pudo descargar {package}.\n{detalle}")
