from dataclasses import dataclass
from typing import Any


@dataclass
class ValorParametro:
    """Resultado de un parámetro: valor normalizable + evidencia que lo respalda."""

    valor: Any
    detalle: Any

    def a_dict(self) -> dict:
        return {"valor": self.valor, "detalle": self.detalle}


@dataclass
class ContextoAnalisis:
    """Reportes crudos de las fuentes, compartidos por todos los extractores."""

    mobsf: dict
    exodus: dict | None
    exodus_error: str | None

    @property
    def md5(self) -> str:
        return self.mobsf.get("md5", "")
