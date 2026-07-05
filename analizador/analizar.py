import json

import click

from nucleo.config import Configuracion
from nucleo.fuentes.descargador import DescargadorApkeep
from nucleo.fuentes.exodus import ClienteExodus
from nucleo.fuentes.mobsf import ClienteMobSF
from nucleo.fuentes.osv import ClienteOSV
from nucleo.fuentes.playstore import BuscadorPlayStore
from nucleo.fuentes.virustotal import ClienteVirusTotal
from nucleo.parametros import extractores_por_defecto
from nucleo.persistencia import RepositorioResultados
from nucleo.pipeline import Orquestador


def _mobsf(cfg: Configuracion) -> ClienteMobSF:
    return ClienteMobSF(cfg.mobsf_url, cfg.mobsf_api_key)


def _descargador(cfg: Configuracion) -> DescargadorApkeep:
    return DescargadorApkeep(cfg.proyecto_dir, cfg.apks_dir)


def _orquestador(cfg: Configuracion) -> Orquestador:
    """Composition root: único lugar donde se arman las implementaciones
    concretas; el resto del código solo conoce las abstracciones."""
    reputacion = ClienteVirusTotal(cfg.vt_api_key) if cfg.vt_api_key else None
    return Orquestador(
        analisis_estatico=_mobsf(cfg),
        trackers=ClienteExodus(cfg.proyecto_dir, cfg.apks_dir, cfg.resultados_dir),
        extractores=extractores_por_defecto(ClienteOSV(), reputacion),
        repositorio=RepositorioResultados(cfg.resultados_dir),
    )


@click.group()
def cli():
    """Herramienta de evaluación de privacidad/seguridad de apps Android."""


@cli.command()
def estado():
    """Verifica que las herramientas del entorno (MobSF, etc.) estén disponibles."""
    cfg = Configuracion.desde_env()
    if _mobsf(cfg).esta_disponible():
        click.echo(f"[OK] MobSF responde en {cfg.mobsf_url}")
    else:
        click.echo(f"[FALLA] MobSF no responde en {cfg.mobsf_url}")
        raise SystemExit(1)


@cli.command()
@click.argument("apk", type=click.Path(exists=True))
def analizar(apk):
    """Corre MobSF + Exodus + OSV + VirusTotal sobre un APK y guarda el JSON
    normalizado en resultados/."""
    click.echo(f"Analizando {apk}...")
    reporte = _orquestador(Configuracion.desde_env()).analizar(apk)
    click.echo(json.dumps(reporte, indent=2, ensure_ascii=False))
    click.echo(f"\n[OK] Reporte guardado en {reporte['meta']['archivo_salida']}")


@cli.command()
@click.argument("nombre")
@click.option("-n", "--limite", default=5, help="Máximo de candidatas a listar.")
def buscar(nombre, limite):
    """Busca apps por nombre en Google Play y lista sus package_name."""
    candidatas = BuscadorPlayStore().buscar(nombre, limite)
    if not candidatas:
        click.echo("Sin resultados.")
        return
    for c in candidatas:
        click.echo(
            f"- {c['package']}\n    {c['titulo']} · {c['developer']} · "
            f"rating {c['rating']} · {c['instalaciones']} instalaciones"
        )


@cli.command(name="analizar-app")
@click.argument("package")
def analizar_app(package):
    """Descarga un APK por package_name (apkeep) y lo analiza."""
    cfg = Configuracion.desde_env()
    click.echo(f"Descargando {package}...")
    apk = _descargador(cfg).descargar(package)
    click.echo(f"[OK] Descargado en {apk}\nAnalizando...")
    reporte = _orquestador(cfg).analizar(str(apk))
    click.echo(json.dumps(reporte, indent=2, ensure_ascii=False))
    click.echo(f"\n[OK] Reporte guardado en {reporte['meta']['archivo_salida']}")


if __name__ == "__main__":
    cli()
