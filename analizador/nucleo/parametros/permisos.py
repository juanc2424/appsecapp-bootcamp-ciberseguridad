from ..modelos import ContextoAnalisis, ValorParametro
from .base import ExtractorParametro

PERMISOS_SENSIBLES = {
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.BODY_SENSORS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.READ_PHONE_STATE",
}


class PermisosPeligrosos(ExtractorParametro):
    nombre = "permisos_peligrosos"

    def extraer(self, ctx: ContextoAnalisis) -> ValorParametro:
        peligrosos = [
            nombre
            for nombre, info in ctx.mobsf.get("permissions", {}).items()
            if info.get("status") == "dangerous"
        ]
        return ValorParametro(len(peligrosos), peligrosos)


class SobrePrivilegio(ExtractorParametro):
    nombre = "sobre_privilegio"

    def extraer(self, ctx: ContextoAnalisis) -> ValorParametro:
        permisos = ctx.mobsf.get("permissions", {})
        total = len(permisos)
        peligrosos = sum(1 for info in permisos.values() if info.get("status") == "dangerous")
        ratio = round(peligrosos / total, 2) if total else 0.0
        return ValorParametro(
            ratio,
            f"{peligrosos}/{total} permisos declarados son 'dangerous' "
            "(proxy estático; no compara contra la función real de la app)",
        )


class CombinacionSensibleInternet(ExtractorParametro):
    nombre = "permiso_sensible_mas_internet"

    def extraer(self, ctx: ContextoAnalisis) -> ValorParametro:
        permisos = set(ctx.mobsf.get("permissions", {}).keys())
        tiene_internet = "android.permission.INTERNET" in permisos
        sensibles_presentes = sorted(permisos & PERMISOS_SENSIBLES)
        return ValorParametro(
            bool(tiene_internet and sensibles_presentes),
            {
                "tiene_internet": tiene_internet,
                "permisos_sensibles_presentes": sensibles_presentes,
            },
        )
