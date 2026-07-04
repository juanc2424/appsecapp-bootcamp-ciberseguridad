import json

import click

from nucleo import config, mobsf_client, pipeline


@click.group()
def cli():
    """Herramienta de evaluación de privacidad/seguridad de apps Android."""


@cli.command()
def estado():
    """Verifica que las herramientas del entorno (MobSF, etc.) estén disponibles."""
    if mobsf_client.esta_disponible():
        click.echo(f"[OK] MobSF responde en {config.MOBSF_URL}")
    else:
        click.echo(f"[FALLA] MobSF no responde en {config.MOBSF_URL}")
        raise SystemExit(1)


@cli.command()
@click.argument("apk", type=click.Path(exists=True))
def analizar(apk):
    """Corre MobSF + Exodus sobre un APK y guarda el JSON normalizado en resultados/."""
    click.echo(f"Analizando {apk}...")
    reporte = pipeline.analizar(apk)
    click.echo(json.dumps(reporte, indent=2, ensure_ascii=False))
    click.echo(f"\n[OK] Reporte guardado en {reporte['meta']['archivo_salida']}")


if __name__ == "__main__":
    cli()
