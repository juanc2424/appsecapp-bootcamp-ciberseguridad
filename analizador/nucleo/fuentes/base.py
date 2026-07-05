"""Interfaces de las fuentes de análisis.

El resto del código depende de estas abstracciones, no de las
implementaciones concretas: cambiar MobSF por otro analizador estático, o
VirusTotal por otro servicio de reputación, no obliga a tocar el pipeline
ni los extractores (inversión de dependencias + sustitución de Liskov).
"""

from abc import ABC, abstractmethod
from pathlib import Path


class FuenteReporteApk(ABC):
    """Herramienta que analiza un APK y devuelve su reporte crudo."""

    @abstractmethod
    def analizar(self, ruta_apk: Path) -> dict: ...


class FuenteReputacion(ABC):
    """Servicio que responde la reputación de un archivo por su hash."""

    @abstractmethod
    def consultar(self, hash_archivo: str) -> dict | None:
        """Resumen de detecciones, o None si el hash no está en la base."""


class FuenteVulnerabilidades(ABC):
    """Base de datos de vulnerabilidades consultable por paquete."""

    @abstractmethod
    def vulnerabilidades(self, paquete: str) -> list[dict]: ...


class Verificable(ABC):
    """Fuente cuya disponibilidad puede comprobarse antes de usarla."""

    @abstractmethod
    def esta_disponible(self) -> bool: ...


class BuscadorApps(ABC):
    """Busca apps por nombre y devuelve candidatas con su metadata."""

    @abstractmethod
    def buscar(self, texto: str, limite: int = 5) -> list[dict]:
        """Cada candidata: package, titulo, developer, rating, instalaciones."""


class DescargadorApk(ABC):
    """Descarga el APK de una app por su package_name y devuelve la ruta local."""

    @abstractmethod
    def descargar(self, package: str) -> Path: ...
