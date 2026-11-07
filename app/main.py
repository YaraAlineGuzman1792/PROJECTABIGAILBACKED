"""Project Abigail — Registro de Partidas.

Punto de entrada: cabeceras de seguridad, límite de tasa, límite de tamaño de
cuerpo, CORS restringido y montaje de los enrutadores.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from threading import Lock

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import obtener_config
from .database import FabricaSesion, crear_tablas
from .models import Administrador, ahora
from .routers import admin, juego
from .schemas import Salud
from .security import cripto

log = logging.getLogger("abigail")
cfg = obtener_config()


def preparar_administrador() -> str:
    """Crea la cuenta de administración a partir del entorno, si falta.

    Permite que el servicio quede utilizable en un despliegue nuevo sin tener
    que entrar por consola a ejecutar un script.
    """
    hash_configurado = cfg.admin_password_hash
    if not hash_configurado and cfg.admin_password:
        hash_configurado = cripto.hash_password(cfg.admin_password)
    if not hash_configurado:
        return "sin credenciales de administración configuradas"

    with FabricaSesion() as bd:
        cuenta = bd.get(Administrador, cfg.admin_usuario)
        if cuenta is None:
            bd.add(Administrador(usuario=cfg.admin_usuario,
                                 password_hash=hash_configurado))
            bd.commit()
            return f"cuenta «{cfg.admin_usuario}» creada"
        return f"cuenta «{cfg.admin_usuario}» ya existía"


@asynccontextmanager
async def ciclo_vida(_: "FastAPI"):
    crear_tablas()
    log.info("Administración: %s", preparar_administrador())
    yield


app = FastAPI(
    lifespan=ciclo_vida,
    title=cfg.nombre_servicio,
    version=cfg.version,
    description=(
        "Registro de partidas del prototipo Project Abigail.\n\n"
        "Cada partida se abre con una clave efímera y toda petición posterior "
        "va firmada con HMAC-SHA256 sobre los bytes exactos enviados. Los "
        "datos son anónimos: no se guarda nombre, correo ni dirección IP en "
        "claro, sólo una huella derivada del origen para limitar el abuso."
    ),
    docs_url="/docs" if not cfg.es_produccion else None,
    redoc_url=None,
    openapi_url="/openapi.json" if not cfg.es_produccion else None,
)

if cfg.origenes_permitidos:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.origenes_permitidos,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", "X-Marca-Tiempo",
                       "X-Nonce", "X-Firma"],
        max_age=600,
    )


# --------------------------------------------------------------- límite de tasa
_ventanas: dict[str, deque[float]] = defaultdict(deque)
_candado = Lock()
_ULTIMA_PURGA = [0.0]


def _permitido(clave: str, limite: int, ventana_s: int = 60) -> bool:
    """Ventana deslizante en memoria.

    Basta para una sola instancia, que es el despliegue previsto. Si algún día
    hay varias réplicas, esto debe pasar a Redis: cada réplica contaría aparte.
    """
    t = time.monotonic()
    with _candado:
        # Purga periódica para que el diccionario no crezca sin límite.
        if t - _ULTIMA_PURGA[0] > 300:
            for k in [k for k, v in _ventanas.items() if not v or t - v[-1] > 600]:
                del _ventanas[k]
            _ULTIMA_PURGA[0] = t

        cola = _ventanas[clave]
        while cola and t - cola[0] > ventana_s:
            cola.popleft()
        if len(cola) >= limite:
            return False
        cola.append(t)
        return True


@app.middleware("http")
async def proteccion(request: Request, call_next):
    # Límite de tamaño: evita que un cuerpo enorme agote memoria antes de validar.
    largo = request.headers.get("content-length")
    if largo and largo.isdigit() and int(largo) > cfg.max_cuerpo_bytes:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"detail": f"El cuerpo excede {cfg.max_cuerpo_bytes} bytes."},
        )

    # Límite de tasa por origen, antes de tocar la base de datos.
    if request.url.path.startswith("/v1"):
        ip = request.client.host if request.client else "desconocido"
        if cfg.cabecera_ip_confiable:
            reenviada = request.headers.get(cfg.cabecera_ip_confiable)
            if reenviada:
                ip = reenviada.split(",")[0].strip()
        if not _permitido(f"ip:{ip}", cfg.limite_peticiones_por_ip_minuto):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Demasiadas peticiones. Intente de nuevo en un minuto."},
                headers={"Retry-After": "60"},
            )

    respuesta = await call_next(request)

    respuesta.headers["X-Content-Type-Options"] = "nosniff"
    respuesta.headers["X-Frame-Options"] = "DENY"
    respuesta.headers["Referrer-Policy"] = "no-referrer"
    respuesta.headers["Cache-Control"] = "no-store"
    respuesta.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    respuesta.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if cfg.es_produccion:
        respuesta.headers["Strict-Transport-Security"] = \
            "max-age=63072000; includeSubDomains; preload"
    if "server" in respuesta.headers:
        del respuesta.headers["server"]
    return respuesta


@app.exception_handler(Exception)
async def error_no_controlado(request: Request, exc: Exception):
    """No se filtran trazas ni detalles internos al cliente."""
    log.exception("Error no controlado en %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Error interno del servidor."})


app.include_router(juego.router)
app.include_router(admin.router)


@app.get("/salud", response_model=Salud, tags=["servicio"], summary="Estado del servicio")
def salud():
    return Salud(estado="operativo", version=cfg.version, entorno=cfg.entorno)
