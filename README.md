# AppSecApp — entorno del proyecto (Equipo 8)

Herramienta de evaluación de privacidad/seguridad de apps Android.

## Requisitos

- Docker Desktop.
- **macOS:** dar acceso a Docker en *Configuración del Sistema → Privacidad y
  Seguridad → Archivos y Carpetas* para la carpeta del proyecto (además de la
  lista de *File sharing* de Docker Desktop), o los volúmenes fallan con
  `operation not permitted`.
- Python 3.11+ en el host (el orquestador `analizar.py` corre local, no en
  contenedor — ver "Arquitectura" abajo).

## Arquitectura

El orquestador (`analizador/analizar.py`) corre **en el host** dentro de un
venv, no dentro de un contenedor. Solo las herramientas pesadas van en Docker:

| Servicio | Qué hace | Cómo se usa |
|---|---|---|
| `mobsf` | Análisis estático (permisos, storage, TLS/cleartext, configs). Queda arriba en `:8000`, el host le habla por REST. | `docker compose up -d mobsf` |
| `exodus` | `exodus-standalone` (trackers). Imagen solo `amd64`; en Apple Silicon se emula (`platform: linux/amd64`). El CLI lo invoca por subprocess. | `docker compose run --rm exodus /apks/<archivo>.apk` |

(Se descartó correr el orquestador dentro de un contenedor `analizador`
porque necesitaría montar el socket de Docker del host —
docker-outside-of-docker— para poder lanzar el contenedor de `exodus`, lo
cual da al contenedor control total sobre Docker del host. Más simple y más
seguro correrlo directo en el host.)

## Primer arranque

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r analizador/requirements.txt

cp .env.example .env
docker compose up -d mobsf              # espera a que quede "healthy"
docker compose logs mobsf | grep -i "API Key"   # copiar a MOBSF_API_KEY en .env

cd analizador
python3 analizar.py estado              # smoke test: confirma que MobSF responde
```

APKs de prueba van en `apks/` (ignorado por git); los reportes se guardan en
`resultados/` (también ignorado).

## Analizar un APK

```bash
source .venv/bin/activate   # si no está activo
cd analizador
python3 analizar.py analizar ../apks/<archivo>.apk
```

Corre **MobSF** (upload → scan → report_json) + **Exodus** (`docker compose
run`) + **OSV.dev** (CVE de los SDKs/trackers detectados) + **VirusTotal**
(reputación, si hay `VT_API_KEY`), y guarda en `resultados/<archivo>.json`
un reporte normalizado con los parámetros definidos en el analizador.

El reporte trae 11 parámetros. 9 se extraen automáticamente. Solo
**minimización de datos** y **declaración vs. realidad** no son evaluables con
análisis estático y quedan marcados como pendientes de revisión manual
(Fase 4). **Procedencia/reputación** requiere `VT_API_KEY` (VirusTotal,
gratis, 4 req/min) — si no está configurada queda marcado como no evaluado,
sin romper el pipeline.

## Apagar

```bash
docker compose down
```

## Estado actual

- **Fase 0** (entorno): lista.
- **Fase 1** (integración de MobSF + Exodus + OSV.dev + VirusTotal, y
  extracción de parámetros): lista — probada end-to-end contra 2 APKs reales
  (F-Droid como respetuosa, Clean Master como abusiva).
- Pendiente: Fase 2 (definir pesos en la matriz Parámetro→Seguridad),
  Fase 3 (fórmula de scoring + semáforo bajo/medio/alto), completar el set de
  apps (faltan las 3-5 comunes).
