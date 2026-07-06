import json
from pathlib import Path

import click

from nucleo import lote
from nucleo.config import Configuracion
from nucleo.fuentes.base import DescargadorApk
from nucleo.fuentes.descargador import DescargadorApkeep
from nucleo.fuentes.descargador_con_fallback import DescargadorConFallback
from nucleo.fuentes.exodus import ClienteExodus
from nucleo.fuentes.mobsf import ClienteMobSF
from nucleo.fuentes.osv import ClienteOSV
from nucleo.fuentes.playstore import BuscadorPlayStore
from nucleo.fuentes.virustotal import ClienteVirusTotal
from nucleo.parametros import extractores_por_defecto
from nucleo.persistencia import RepositorioResultados
from nucleo.pipeline import Orquestador
from nucleo.puntaje import calculadora_por_defecto


def _mobsf(cfg: Configuracion) -> ClienteMobSF:
    return ClienteMobSF(cfg.mobsf_url, cfg.mobsf_api_key)


def _descargador(cfg: Configuracion) -> DescargadorApk:
    descargadores = [DescargadorApkeep(cfg.proyecto_dir, cfg.apks_dir, fuente="apk-pure")]
    if cfg.google_play_email and cfg.google_play_aas_token:
        descargadores.append(DescargadorApkeep(
            cfg.proyecto_dir, cfg.apks_dir, fuente="google-play",
            google_play_email=cfg.google_play_email,
            google_play_aas_token=cfg.google_play_aas_token,
        ))
    return DescargadorConFallback(descargadores)


def _orquestador(cfg: Configuracion) -> Orquestador:
    """Composition root: único lugar donde se arman las implementaciones
    concretas; el resto del código solo conoce las abstracciones."""
    reputacion = ClienteVirusTotal(cfg.vt_api_key) if cfg.vt_api_key else None
    return Orquestador(
        analisis_estatico=_mobsf(cfg),
        trackers=ClienteExodus(cfg.proyecto_dir, cfg.apks_dir, cfg.resultados_dir),
        extractores=extractores_por_defecto(ClienteOSV(), reputacion),
        repositorio=RepositorioResultados(cfg.resultados_dir),
        calculadora=calculadora_por_defecto(),
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


@cli.command(name="analizar-lote")
@click.option(
    "--archivo", "-f",
    type=click.Path(exists=True),
    default=lambda: str(Configuracion.desde_env().proyecto_dir / "dataset_packages.txt"),
    help="Archivo con un package por línea (default: dataset_packages.txt).",
)
def analizar_lote_cmd(archivo):
    """Descarga y analiza en lote todos los packages del dataset.

    Es reanudable (salta los que ya tienen reporte) y no se detiene ante un
    fallo individual. Al final consolida todo en resultados/resumen.csv.
    """
    cfg = Configuracion.desde_env()
    packages = lote.leer_packages(Path(archivo))
    click.echo(f"{len(packages)} packages en {archivo}\n")

    estados = lote.analizar_lote(
        _descargador(cfg), _orquestador(cfg), packages, cfg.resultados_dir,
        log=click.echo,
    )

    resumen = {}
    for e in estados:
        resumen[e["estado"]] = resumen.get(e["estado"], 0) + 1
    click.echo(f"\n=== Resumen del lote: {resumen} ===")

    filas = lote.consolidar(cfg.resultados_dir, cfg.resultados_dir / "resumen.csv", calculadora_por_defecto())
    click.echo(f"[OK] {len(filas)} reportes consolidados en {cfg.resultados_dir / 'resumen.csv'}")


@cli.command()
def resumen():
    """Consolida todos los reportes de resultados/ en una tabla CSV para el scoring."""
    cfg = Configuracion.desde_env()
    salida = cfg.resultados_dir / "resumen.csv"
    filas = lote.consolidar(cfg.resultados_dir, salida, calculadora_por_defecto())
    click.echo(f"[OK] {len(filas)} apps consolidadas en {salida}")


if __name__ == "__main__":
    cli()
