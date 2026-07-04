from abc import ABC, abstractmethod
from typing import ClassVar

from ..modelos import ContextoAnalisis, ValorParametro


class ExtractorParametro(ABC):
    """Un parámetro de la matriz Parámetro→Seguridad (hoja de ruta §3).

    Para agregar un parámetro nuevo basta con crear una subclase y sumarla
    a extractores_por_defecto(); el pipeline no se toca (abierto/cerrado).
    """

    nombre: ClassVar[str]

    @abstractmethod
    def extraer(self, ctx: ContextoAnalisis) -> ValorParametro: ...
