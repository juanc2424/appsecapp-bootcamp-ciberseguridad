"""Ejecuta `docker compose` sin depender del PATH del proceso que arranca.

Cuando el orquestador se lanza desde la GUI de Streamlit (o cualquier proceso
que no herede el PATH del shell), `docker` no queda en el PATH y subprocess
falla. Este helper resuelve el binario a una ruta absoluta y normaliza el PATH,
para que tanto el descargador como Exodus funcionen igual desde CLI o GUI.
"""

import os
import shutil
import subprocess
from pathlib import Path

# Ubicaciones habituales del binario de Docker Desktop / Homebrew en macOS.
_RUTAS_CANDIDATAS = (
    "/usr/local/bin/docker",
    "/opt/homebrew/bin/docker",
    "/usr/bin/docker",
)


def _resolver_docker() -> str:
    ruta = shutil.which("docker")
    if ruta:
        return ruta
    for candidata in _RUTAS_CANDIDATAS:
        if Path(candidata).exists():
            return candidata
    raise RuntimeError(
        "No se encontró el binario 'docker'. ¿Está Docker Desktop instalado y en marcha?"
    )


def correr(args: list[str], cwd: Path, **kwargs) -> subprocess.CompletedProcess:
    """Corre `docker compose <args>` en `cwd` con un entorno saneado.

    subprocess falla con un críptico `TypeError: ... not NoneType` si el
    programa, el cwd, algún argumento o cualquier valor del `env` es None.
    Bajo Streamlit el `os.environ` puede traer entradas None que rompen el
    fork/exec aunque el PATH esté bien, así que aquí se saneia todo y, si
    algo sigue mal, se lanza un error legible en vez del TypeError.
    """
    docker = _resolver_docker()

    # env: solo pares str→str; garantiza PATH con la carpeta de docker incluida.
    env = {k: v for k, v in os.environ.items() if isinstance(k, str) and isinstance(v, str)}
    path = env.get("PATH") or "/usr/local/bin:/usr/bin:/bin"
    dir_docker = str(Path(docker).parent)
    if dir_docker not in path.split(os.pathsep):
        path = f"{dir_docker}{os.pathsep}{path}"
    env["PATH"] = path

    comando = [docker, "compose", *args]
    malos = [a for a in comando if not isinstance(a, str)]
    if malos:
        raise ValueError(f"Argumentos inválidos para docker compose: {malos}")

    return subprocess.run(comando, cwd=str(cwd), env=env, **kwargs)
