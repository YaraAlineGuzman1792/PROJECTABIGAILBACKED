"""Bitácora de auditoría encadenada por hash.

Cada entrada incluye el hash de la anterior. Alterar o borrar un registro
rompe la cadena a partir de ese punto, y la ruptura es detectable recorriendo
la bitácora de principio a fin. No impide que alguien con acceso de escritura
a la base de datos manipule los registros, pero sí impide que lo haga sin
dejar evidencia.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import EntradaBitacora, ahora, como_utc

GENESIS = "0" * 64
Severidad = Literal["info", "alerta", "critico"]


def _hash_entrada(secuencia_previa: int, hash_previo: str, evento: str,
                  sesion_id: str | None, severidad: str, detalle: dict,
                  momento: str) -> str:
    material = json.dumps(
        {
            "sec": secuencia_previa + 1,
            "prev": hash_previo,
            "evento": evento,
            "sesion": sesion_id,
            "sev": severidad,
            "detalle": detalle,
            "ts": momento,
        },
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    return hashlib.sha256(material.encode()).hexdigest()


def registrar(bd: Session, evento: str, *, sesion_id: str | None = None,
              severidad: Severidad = "info", **detalle: Any) -> EntradaBitacora:
    ultima = bd.execute(
        select(EntradaBitacora).order_by(EntradaBitacora.secuencia.desc()).limit(1)
    ).scalar_one_or_none()

    hash_previo = ultima.hash_entrada if ultima else GENESIS
    secuencia_previa = ultima.secuencia if ultima else 0
    momento = ahora()

    entrada = EntradaBitacora(
        ocurrido_en=momento,
        evento=evento,
        sesion_id=sesion_id,
        severidad=severidad,
        detalle=detalle,
        hash_previo=hash_previo,
        # Se firma la fecha ya normalizada a UTC, la misma forma que usará
        # verificar_cadena al releerla. Aquí es una conversión vacía, pero
        # deja las dos mitades escritas de la misma manera.
        hash_entrada=_hash_entrada(secuencia_previa, hash_previo, evento,
                                   sesion_id, severidad, detalle,
                                   como_utc(momento).isoformat()),
    )
    bd.add(entrada)
    bd.flush()
    return entrada


def verificar_cadena(bd: Session) -> tuple[bool, int | None]:
    """Recorre la bitácora y comprueba su integridad.

    Devuelve (True, None) si la cadena está intacta, o (False, secuencia) con
    el número de la primera entrada que no cuadra.
    """
    entradas = bd.execute(
        select(EntradaBitacora).order_by(EntradaBitacora.secuencia.asc())
    ).scalars().all()

    hash_previo = GENESIS
    for i, e in enumerate(entradas):
        if e.hash_previo != hash_previo:
            return False, e.secuencia
        normalizado = como_utc(e.ocurrido_en)
        momento = normalizado.isoformat() if normalizado else ""
        esperado = _hash_entrada(i, hash_previo, e.evento, e.sesion_id,
                                 e.severidad, e.detalle, momento)
        if esperado != e.hash_entrada:
            return False, e.secuencia
        hash_previo = e.hash_entrada
    return True, None
