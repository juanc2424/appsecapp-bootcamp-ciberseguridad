import json
from pathlib import Path


class RepositorioResultados:
    """Guarda los reportes normalizados en resultados/."""

    def __init__(self, directorio: Path):
        self._directorio = directorio

    def guardar(self, reporte: dict, nombre_base: str) -> Path:
        salida = self._directorio / f"{nombre_base}.json"
        with open(salida, "w") as f:
            json.dump(reporte, f, indent=2, ensure_ascii=False)
        return salida
