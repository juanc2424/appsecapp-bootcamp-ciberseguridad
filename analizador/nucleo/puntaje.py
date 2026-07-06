"""Índice de riesgo 0-100 a partir de los parámetros extraídos.

Indicador compuesto aditivo (suma ponderada de componentes normalizados),
construido según el Handbook OECD/JRC de indicadores compuestos y calibrado
por contraste de roles sobre el dataset de 48 apps. La justificación de cada
peso, la normalización y los umbrales del semáforo están documentados en
`scoring_metodologia.md` (raíz del proyecto final).
"""

import math
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class ComponentePuntaje:
    """Un sumando del índice: peso × normalización sobre los parámetros.

    `normalizar` recibe el dict `reporte["parametros"]` completo y devuelve
    un valor en [0, 1]; así cada componente decide de qué parámetro(s) lee
    sin que la calculadora conozca sus detalles (abierto/cerrado)."""

    nombre: str
    peso: float
    normalizar: Callable[[dict], float]


class CalculadoraRiesgo:
    """Agrega los componentes en un score 0-100 con semáforo.

    Umbrales anclados en los terciles observados del dataset (p33=31.8,
    p66=40.5), redondeados: bajo < 30 ≤ medio ≤ 45 < alto."""

    UMBRAL_BAJO = 30
    UMBRAL_ALTO = 45

    def __init__(self, componentes: list[ComponentePuntaje]):
        self._componentes = componentes

    def calcular(self, parametros: dict) -> dict:
        desglose = {
            c.nombre: round(c.peso * min(max(c.normalizar(parametros), 0.0), 1.0), 1)
            for c in self._componentes
        }
        total = round(sum(desglose.values()), 1)
        return {"total": total, "semaforo": self._semaforo(total), "desglose": desglose}

    def _semaforo(self, total: float) -> str:
        if total < self.UMBRAL_BAJO:
            return "bajo"
        if total <= self.UMBRAL_ALTO:
            return "medio"
        return "alto"


def _valor(parametros: dict, nombre: str, defecto=0):
    v = (parametros.get(nombre) or {}).get("valor")
    return defecto if v is None else v


def _capado(nombre: str, cap: float) -> Callable[[dict], float]:
    """Min-max winsorizado: min(x, cap) / cap (robusto a outliers, OECD)."""
    return lambda p: min(float(_valor(p, nombre)), cap) / cap


def _booleano(nombre: str) -> Callable[[dict], float]:
    return lambda p: 1.0 if _valor(p, nombre, False) else 0.0


def _reputacion(parametros: dict) -> float:
    """0 detecciones AV → 0 · 1-2 → 0.6 · ≥3 → 1.0 · sin hash en VT → 0.5.

    Convención de la investigación con AndroZoo/VirusTotal: ≥4 detecciones se
    trata como malware confirmado y 1-3 como zona gris; no estar en la base
    es señal de procedencia desconocida."""
    detalle = (parametros.get("procedencia_reputacion") or {}).get("detalle")
    if not isinstance(detalle, dict):
        return 0.5
    maliciosos = detalle.get("maliciosos") or 0
    if maliciosos == 0:
        return 0.0
    return 0.6 if maliciosos <= 2 else 1.0


def _config_log(parametros: dict) -> float:
    """Compresión logarítmica: el conteo crudo de componentes exportados crece
    con el tamaño de la app, no con su riesgo (mainstream 68.8 vs abusivas 7-12)."""
    x = float(_valor(parametros, "config_inseguras"))
    return min(math.log1p(x) / math.log1p(150), 1.0)


def calculadora_por_defecto() -> CalculadoraRiesgo:
    """Pesos calibrados por contraste de roles (ver scoring_metodologia.md §2).

    Excluidos por fallar la validación empírica (§4): cve_en_sdks (todo ceros),
    sobre_privilegio (artefacto de denominador pequeño), mobsf_security_score
    (índice compuesto: doble conteo)."""
    return CalculadoraRiesgo([
        ComponentePuntaje("trackers", 30, _capado("trackers", 20)),
        ComponentePuntaje("reputacion", 25, _reputacion),
        ComponentePuntaje("permisos", 12, _capado("permisos_peligrosos", 25)),
        ComponentePuntaje("almacenamiento", 10, _capado("almacenamiento_inseguro", 8)),
        ComponentePuntaje("configuracion", 10, _config_log),
        ComponentePuntaje("cifrado", 8, _booleano("cifrado_transito_inseguro")),
        ComponentePuntaje("sensible_internet", 5, _booleano("permiso_sensible_mas_internet")),
    ])
