"""GUI sencilla (Streamlit) para el flujo buscar → elegir → descargar → analizar.

Correr desde AppSecApp/ con el venv activo y MobSF arriba:
    streamlit run analizador/gui.py
"""

import streamlit as st

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

cfg = Configuracion.desde_env()


def orquestador() -> Orquestador:
    reputacion = ClienteVirusTotal(cfg.vt_api_key) if cfg.vt_api_key else None
    return Orquestador(
        analisis_estatico=ClienteMobSF(cfg.mobsf_url, cfg.mobsf_api_key),
        trackers=ClienteExodus(cfg.proyecto_dir, cfg.apks_dir, cfg.resultados_dir),
        extractores=extractores_por_defecto(ClienteOSV(), reputacion),
        repositorio=RepositorioResultados(cfg.resultados_dir),
    )


st.set_page_config(page_title="AppSec — Evaluador de privacidad", page_icon="🔒")
st.title("🔒 Evaluador de privacidad de apps Android")
st.caption("Busca una app, descárgala y analiza sus permisos, trackers y riesgos.")

if not ClienteMobSF(cfg.mobsf_url, cfg.mobsf_api_key).esta_disponible():
    st.error(
        f"MobSF no responde en {cfg.mobsf_url}. "
        "Levántalo con `docker compose up -d mobsf` antes de analizar."
    )

nombre = st.text_input("Nombre de la app", placeholder="ej. Clean Master, Instagram…")

# El package elegido puede venir de la búsqueda o escribirse a mano (útil para
# apps cuyo "resultado destacado" no expone su appId en la búsqueda).
package_elegido = None

if nombre:
    with st.spinner("Buscando en Google Play…"):
        candidatas = BuscadorPlayStore().buscar(nombre, limite=6)

    if not candidatas:
        st.warning("Sin resultados con package descargable.")
    else:
        opciones = {
            f"{c['titulo']} — {c['developer']} "
            f"({c['instalaciones']}, ★{c['rating']})": c
            for c in candidatas
        }
        elegida = st.radio("Elige una:", list(opciones.keys()))
        package_elegido = opciones[elegida]["package"]

package_manual = st.text_input(
    "…o pega el package directamente",
    placeholder="ej. com.instagram.android",
    help="El package aparece en la URL de Play Store: play.google.com/store/apps/details?id=<package>",
)
if package_manual.strip():
    package_elegido = package_manual.strip()

if package_elegido:
    st.write(f"**Package a analizar:** `{package_elegido}`")

    if st.button("Descargar y analizar", type="primary"):
        with st.spinner(f"Descargando {package_elegido}…"):
            apk = DescargadorApkeep(cfg.proyecto_dir, cfg.apks_dir).descargar(
                package_elegido
            )
        st.success(f"Descargado: {apk.name}")

        with st.spinner("Analizando (MobSF + Exodus + OSV + VirusTotal)… "
                        "puede tardar varios minutos."):
            reporte = orquestador().analizar(str(apk))

        st.success("Análisis completo.")
        app = reporte["app"]
        st.subheader(f"{app['app_name']} · {app['version_name']}")
        st.metric("MobSF security score", app["mobsf_security_score"])

        p = reporte["parametros"]
        st.write(f"**Permisos peligrosos:** {p['permisos_peligrosos']['valor']}")
        st.write(f"**Trackers:** {p['trackers']['valor']}")
        st.write(
            f"**Componentes exportados sin proteger:** "
            f"{p['config_inseguras']['detalle']['componentes_exportados_sin_proteger']}"
        )
        with st.expander("Ver reporte completo (JSON)"):
            st.json(reporte)
        st.caption(f"Guardado en {reporte['meta']['archivo_salida']}")
