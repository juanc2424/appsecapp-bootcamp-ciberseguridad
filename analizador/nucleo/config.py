import os
import pathlib
from dataclasses import dataclass

from dotenv import load_dotenv

# Raíz del proyecto (AppSecApp/), donde vive docker-compose.yml.
_PROYECTO_DIR = pathlib.Path(__file__).resolve().parent.parent.parent


@dataclass(frozen=True)
class Configuracion:
    """Configuración inmutable del entorno; se inyecta donde haga falta en
    lugar de leerse como estado global de módulo."""

    mobsf_url: str
    mobsf_api_key: str
    vt_api_key: str
    proyecto_dir: pathlib.Path
    apks_dir: pathlib.Path
    resultados_dir: pathlib.Path

    @classmethod
    def desde_env(cls) -> "Configuracion":
        load_dotenv(_PROYECTO_DIR / ".env")
        return cls(
            mobsf_url=os.getenv("MOBSF_URL", "http://localhost:8000"),
            mobsf_api_key=os.getenv("MOBSF_API_KEY", ""),
            vt_api_key=os.getenv("VT_API_KEY", ""),
            proyecto_dir=_PROYECTO_DIR,
            apks_dir=_PROYECTO_DIR / "apks",
            resultados_dir=_PROYECTO_DIR / "resultados",
        )
