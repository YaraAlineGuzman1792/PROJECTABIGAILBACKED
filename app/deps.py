"""Dependencias de autenticación y control de acceso.

`sesion_autenticada` es la puerta por la que pasa toda petición del juego.
Encadena siete comprobaciones y cualquiera de ellas corta el paso:

  1. token de sesión presente y firmado por el servidor
  2. la sesión existe, no está revocada y no ha expirado
  3. la marca de tiempo cae dentro de la ventana admitida
  4. el nonce no se ha visto antes (anti-repetición)
  5. la firma HMAC del cuerpo exacto es válida
  6. la sesión no excede su límite de peticiones
  7. el identificador de la ruta coincide con el de la sesión del token
"""
from __future__ import annotations

import time
from datetime import timedelta
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session as BDSession

from . import audit
from .config import Config, obtener_config
from .database import obtener_bd
from .models import Administrador, Nonce, Sesion, ahora, como_utc
from .security import cripto, tokens

BD = Annotated[BDSession, Depends(obtener_bd)]
Cfg = Annotated[Config, Depends(obtener_config)]


def _rechazar(codigo: int, detalle: str, cabecera: str | None = None):
    cabeceras = {"WWW-Authenticate": cabecera} if cabecera else None
    return HTTPException(status_code=codigo, detail=detalle, headers=cabeceras)


def _rechazar_persistiendo(bd: BDSession, codigo: int, detalle: str,
                           cabecera: str | None = None):
    """Rechaza la petición conservando lo ya escrito.

    La dependencia de base de datos revierte la transacción cuando se lanza
    una excepción. Para los eventos de seguridad eso sería contraproducente:
    el rastro de un intento de fraude se perdería justo al rechazarlo. Aquí se
    confirma la escritura antes de cortar.
    """
    bd.commit()
    return _rechazar(codigo, detalle, cabecera)


def origen_de(request: Request, cfg: Config) -> str:
    """Seudónimo estable del origen de la petición. Nunca se guarda la IP."""
    directo = request.client.host if request.client else "desconocido"
    reenviado = request.headers.get("x-forwarded-for", "")
    bruto = reenviado.split(",")[0].strip() or directo
    return cripto.huella_origen(cfg.clave_maestra_bytes(), bruto)


async def sesion_autenticada(
    request: Request,
    bd: BD,
    cfg: Cfg,
    authorization: Annotated[str | None, Header()] = None,
    x_marca_tiempo: Annotated[str | None, Header()] = None,
    x_nonce: Annotated[str | None, Header()] = None,
    x_firma: Annotated[str | None, Header()] = None,
) -> Sesion:
    # 1 · Token
    if not authorization or not authorization.lower().startswith("bearer "):
        raise _rechazar(status.HTTP_401_UNAUTHORIZED,
                        "Falta el token de sesión.", "Bearer")
    token = authorization.split(" ", 1)[1].strip()
    try:
        carga = tokens.leer_token_sesion(cfg.clave_maestra_bytes(), token)
    except tokens.TokenInvalido:
        raise _rechazar(status.HTTP_401_UNAUTHORIZED,
                        "Token de sesión inválido o expirado.", "Bearer")
    sesion_id = carga["sub"]

    # 2 · Sesión
    sesion = bd.get(Sesion, sesion_id)
    if sesion is None:
        raise _rechazar(status.HTTP_401_UNAUTHORIZED, "La sesión no existe.")
    if not sesion.vigente():
        audit.registrar(bd, "sesion_no_vigente", sesion_id=sesion_id, severidad="alerta",
                        revocada=sesion.revocada)
        raise _rechazar_persistiendo(bd, status.HTTP_401_UNAUTHORIZED,
                                     "La sesión está revocada o ha expirado.")

    # 3 · Marca de tiempo
    if not x_marca_tiempo or not x_marca_tiempo.isdigit():
        raise _rechazar(status.HTTP_400_BAD_REQUEST,
                        "Falta la cabecera X-Marca-Tiempo o no es un entero.")
    desfase = abs(int(time.time()) - int(x_marca_tiempo))
    if desfase > cfg.ventana_firma_segundos:
        audit.registrar(bd, "marca_tiempo_fuera_de_ventana", sesion_id=sesion_id,
                        severidad="alerta", desfase_segundos=desfase)
        raise _rechazar_persistiendo(
            bd, status.HTTP_400_BAD_REQUEST,
            f"La marca de tiempo está fuera de la ventana de "
            f"{cfg.ventana_firma_segundos} s (desfase: {desfase} s).")

    # 4 · Nonce
    if not x_nonce or len(x_nonce) != 32 or not all(c in "0123456789abcdef" for c in x_nonce):
        raise _rechazar(status.HTTP_400_BAD_REQUEST,
                        "El nonce debe ser una cadena de 32 caracteres hexadecimales.")
    corte = ahora() - timedelta(seconds=cfg.retencion_nonce_segundos)
    bd.execute(delete(Nonce).where(Nonce.visto_en < corte))
    if bd.get(Nonce, x_nonce) is not None:
        audit.registrar(bd, "nonce_repetido", sesion_id=sesion_id, severidad="critico",
                        nonce=x_nonce)
        sesion.rechazos += 1
        raise _rechazar_persistiendo(
            bd, status.HTTP_409_CONFLICT,
            "Nonce ya utilizado: la petición se interpreta como repetición.")

    # 5 · Firma
    cuerpo = await request.body()
    clave = cripto.derivar_clave_sesion(cfg.clave_maestra_bytes(), sesion_id)
    if cripto.huella_clave(clave) != sesion.huella_clave:
        audit.registrar(bd, "huella_clave_discrepante", sesion_id=sesion_id,
                        severidad="critico")
        raise _rechazar_persistiendo(bd, status.HTTP_401_UNAUTHORIZED,
                                     "Clave de sesión inconsistente.")

    valida = cripto.verificar_firma(
        clave, x_firma or "", request.method, request.url.path,
        x_marca_tiempo, x_nonce, cuerpo,
    )
    if not valida:
        sesion.rechazos += 1
        audit.registrar(bd, "firma_invalida", sesion_id=sesion_id, severidad="critico",
                        ruta=request.url.path, metodo=request.method)
        if sesion.rechazos >= 10:
            sesion.revocada = True
            sesion.motivo_revocacion = "Diez firmas inválidas consecutivas."
            audit.registrar(bd, "sesion_revocada", sesion_id=sesion_id, severidad="critico",
                            motivo=sesion.motivo_revocacion)
        raise _rechazar_persistiendo(bd, status.HTTP_401_UNAUTHORIZED,
                                     "Firma de la petición inválida.")

    # 6 · Límite de peticiones
    sesion.peticiones += 1
    minutos = max((ahora() - como_utc(sesion.creada_en)).total_seconds() / 60.0, 1.0)
    if sesion.peticiones / minutos > cfg.limite_peticiones_por_sesion_minuto:
        audit.registrar(bd, "limite_tasa_sesion", sesion_id=sesion_id, severidad="alerta",
                        peticiones=sesion.peticiones)
        raise _rechazar_persistiendo(bd, status.HTTP_429_TOO_MANY_REQUESTS,
                                     "Se superó el límite de peticiones de la sesión.")

    # El nonce se consume sólo cuando todo lo anterior fue válido.
    bd.add(Nonce(valor=x_nonce, sesion_id=sesion_id))
    return sesion


def coincide_ruta(sesion_id: str, sesion: Sesion) -> None:
    """7 · El identificador de la ruta debe ser el de la sesión autenticada."""
    if sesion_id != sesion.id:
        raise _rechazar(status.HTTP_403_FORBIDDEN,
                        "El token no corresponde a la sesión indicada en la ruta.")


# ---------------------------------------------------------------------------
async def admin_autenticado(
    bd: BD,
    cfg: Cfg,
    authorization: Annotated[str | None, Header()] = None,
) -> Administrador:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise _rechazar(status.HTTP_401_UNAUTHORIZED,
                        "Falta el token de administración.", "Bearer")
    try:
        carga = tokens.leer_token_admin(cfg.clave_maestra_bytes(),
                                        authorization.split(" ", 1)[1].strip())
    except tokens.TokenInvalido:
        raise _rechazar(status.HTTP_401_UNAUTHORIZED, "Token de administración inválido.")

    admin = bd.get(Administrador, carga["sub"])
    if admin is None:
        raise _rechazar(status.HTTP_401_UNAUTHORIZED, "La cuenta no existe.")
    return admin
