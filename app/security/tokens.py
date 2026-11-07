"""Tokens de sesión y de administración (JWT firmados con HS256)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt

EMISOR = "project-abigail-api"
AUD_JUEGO = "cliente-juego"
AUD_ADMIN = "panel-admin"


class TokenInvalido(Exception):
    pass


def _clave(clave_maestra: bytes) -> bytes:
    return clave_maestra


def emitir_token_sesion(clave_maestra: bytes, sesion_id: str,
                        minutos: int, condicion: str) -> tuple[str, datetime]:
    expira = datetime.now(timezone.utc) + timedelta(minutes=minutos)
    carga = {
        "iss": EMISOR,
        "aud": AUD_JUEGO,
        "sub": sesion_id,
        "cnd": condicion,
        "iat": datetime.now(timezone.utc),
        "exp": expira,
    }
    return jwt.encode(carga, _clave(clave_maestra), algorithm="HS256"), expira


def leer_token_sesion(clave_maestra: bytes, token: str) -> dict:
    try:
        return jwt.decode(
            token, _clave(clave_maestra), algorithms=["HS256"],
            audience=AUD_JUEGO, issuer=EMISOR,
            options={"require": ["exp", "iat", "sub", "aud", "iss"]},
        )
    except jwt.PyJWTError as exc:
        raise TokenInvalido(str(exc)) from exc


def emitir_token_admin(clave_maestra: bytes, usuario: str, minutos: int = 30) -> str:
    carga = {
        "iss": EMISOR,
        "aud": AUD_ADMIN,
        "sub": usuario,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=minutos),
    }
    return jwt.encode(carga, _clave(clave_maestra), algorithm="HS256")


def leer_token_admin(clave_maestra: bytes, token: str) -> dict:
    try:
        return jwt.decode(
            token, _clave(clave_maestra), algorithms=["HS256"],
            audience=AUD_ADMIN, issuer=EMISOR,
            options={"require": ["exp", "iat", "sub", "aud", "iss"]},
        )
    except jwt.PyJWTError as exc:
        raise TokenInvalido(str(exc)) from exc
