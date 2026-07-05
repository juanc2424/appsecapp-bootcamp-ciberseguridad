from google_play_scraper import search

from .base import BuscadorApps


class BuscadorPlayStore(BuscadorApps):
    """Busca apps en Google Play (metadata en vivo; no descarga el APK)."""

    def __init__(self, lang: str = "es", country: str = "co"):
        self._lang = lang
        self._country = country

    def buscar(self, texto: str, limite: int = 5) -> list[dict]:
        # google-play-scraper deja `appId=None` en el "resultado destacado"
        # superior (limitación conocida). Se piden algunos hits extra y se
        # descartan los que no traen package: sin él no se puede descargar y
        # solo romperían el flujo aguas abajo.
        resultados = search(
            texto, lang=self._lang, country=self._country, n_hits=limite + 3
        )
        candidatas = [
            {
                "package": r["appId"],
                "titulo": r["title"],
                "developer": r.get("developer"),
                "rating": r.get("score"),
                "instalaciones": r.get("installs"),
                "icono": r.get("icon"),
            }
            for r in resultados
            if r.get("appId")
        ]
        return candidatas[:limite]
