import os
import pathlib

from dotenv import load_dotenv

# Raíz del proyecto (AppSecApp/), donde vive docker-compose.yml.
PROYECTO_DIR = pathlib.Path(__file__).resolve().parent.parent.parent
APKS_DIR = PROYECTO_DIR / "apks"
RESULTADOS_DIR = PROYECTO_DIR / "resultados"

load_dotenv(PROYECTO_DIR / ".env")

MOBSF_URL = os.getenv("MOBSF_URL", "http://localhost:8000")
MOBSF_API_KEY = os.getenv("MOBSF_API_KEY", "")
VT_API_KEY = os.getenv("VT_API_KEY", "")
