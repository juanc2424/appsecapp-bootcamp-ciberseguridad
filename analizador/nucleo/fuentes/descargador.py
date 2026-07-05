import zipfile
from pathlib import Path

from . import docker_compose
from .base import DescargadorApk


class DescargadorApkeep(DescargadorApk):
    """Descarga APKs por package_name usando el contenedor apkeep (APKPure).

    apkeep puede entregar un `.apk` plano o un `.xapk` (bundle: APK base +
    splits). MobSF/Exodus necesitan un `.apk`, así que si viene `.xapk` se
    extrae el APK base y se descarta el resto (los splits son solo recursos
    de idioma/densidad, irrelevantes para el análisis estático)."""

    def __init__(self, proyecto_dir: Path, apks_dir: Path, fuente: str = "apk-pure"):
        self._proyecto_dir = proyecto_dir
        self._apks_dir = apks_dir
        self._fuente = fuente

    def descargar(self, package: str) -> Path:
        proceso = docker_compose.correr(
            [
                "--profile", "tools", "run", "--rm",
                "apkeep", "-a", package, "-d", self._fuente, "/apks",
            ],
            cwd=self._proyecto_dir,
            capture_output=True,
            text=True,
        )

        apk = self._apks_dir / f"{package}.apk"
        if apk.exists():
            return apk

        xapk = self._apks_dir / f"{package}.xapk"
        if xapk.exists():
            return self._extraer_base(xapk, package)

        raise RuntimeError(
            f"apkeep no dejó ningún APK para {package}.\n"
            f"stdout: {proceso.stdout}\nstderr: {proceso.stderr}"
        )

    def _extraer_base(self, xapk: Path, package: str) -> Path:
        """Saca el APK base (`<package>.apk`) del bundle .xapk."""
        destino = self._apks_dir / f"{package}.apk"
        with zipfile.ZipFile(xapk) as z:
            nombres = z.namelist()
            base = f"{package}.apk"
            if base not in nombres:
                # Algunos bundles nombran el base distinto; se toma el .apk más
                # grande que no sea un split de config.
                candidatos = [
                    n for n in nombres
                    if n.endswith(".apk") and not n.startswith("config.")
                ]
                if not candidatos:
                    raise RuntimeError(f"El .xapk de {package} no contiene un APK base.")
                base = max(candidatos, key=lambda n: z.getinfo(n).file_size)
            with z.open(base) as origen, open(destino, "wb") as salida:
                salida.write(origen.read())
        xapk.unlink()
        return destino
