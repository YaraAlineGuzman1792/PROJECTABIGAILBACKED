"""Endpoints que consume el cliente de Unreal Engine.

Tres operaciones: abrir la partida, ir registrando lo que ocurre y cerrarla
con los indicadores finales.
"""
from __future__ import annotations

import secrets
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from .. import audit
from ..deps import BD, Cfg, coincide_ruta, origen_de, sesion_autenticada
from ..models import EventoPartida, Sesion, ahora, como_utc
from ..schemas import (
    EstadoSesion, LoteEventos, RespuestaCierre, RespuestaSesion,
    SolicitudCierre, SolicitudSesion,
)
from ..security import cripto, tokens

router = APIRouter(prefix="/v1", tags=["partida"])

SesionAuth = Annotated[Sesion, Depends(sesion_autenticada)]


def _siguiente_codigo(bd, condicion: str) -> str:
    """Código visible de la partida, con el formato PA-A-0001.

    Es lo que la persona copia en el cuestionario, así que tiene que ser corto
    y fácil de transcribir. La numeración corre por condición.
    """
    usados = bd.execute(
        select(func.count()).select_from(Sesion).where(Sesion.condicion == condicion)
    ).scalar_one()
    return f"PA-{condicion}-{usados + 1:04d}"


# ---------------------------------------------------------------------------
@router.post("/sesiones", response_model=RespuestaSesion,
             status_code=status.HTTP_201_CREATED,
             summary="Abrir una partida")
def abrir_sesion(datos: SolicitudSesion, request: Request, bd: BD, cfg: Cfg):
    """Crea una partida anónima y entrega su clave de firma.

    Es el único endpoint sin firma HMAC, porque es donde se emite la clave con
    la que se firmará todo lo demás. Se protege con un límite por origen.

    La condición experimental la sortea el servidor salvo que el cliente la
    imponga explícitamente. Que el reparto no dependa del cliente es lo que
    sostiene la inferencia causal del estudio.
    """
    huella = origen_de(request, cfg)
    desde = ahora() - timedelta(hours=1)
    recientes = bd.execute(
        select(func.count()).select_from(Sesion)
        .where(Sesion.huella_origen == huella, Sesion.creada_en >= desde)
    ).scalar_one()
    if recientes >= cfg.limite_sesiones_por_ip_hora:
        audit.registrar(bd, "limite_sesiones_origen", severidad="alerta",
                        huella_origen=huella[:16], recientes=recientes)
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "Se superó el número de partidas por hora para este origen.")

    condicion = datos.condicion or secrets.choice(("A", "B"))

    # El código es único; si dos partidas se abren a la vez pueden calcular el
    # mismo número, así que se reintenta en lugar de fallar.
    for intento in range(5):
        sesion = Sesion(
            codigo=_siguiente_codigo(bd, condicion),
            version_cliente=datos.version_cliente,
            condicion=condicion,
            expira_en=ahora() + timedelta(minutes=cfg.vida_sesion_minutos),
            huella_clave="",
            huella_origen=huella,
        )
        bd.add(sesion)
        try:
            bd.flush()
            break
        except IntegrityError:
            bd.rollback()
            if intento == 4:
                raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                    "No fue posible asignar un código de partida.")

    clave = cripto.derivar_clave_sesion(cfg.clave_maestra_bytes(), sesion.id)
    sesion.huella_clave = cripto.huella_clave(clave)

    token, expira = tokens.emitir_token_sesion(
        cfg.clave_maestra_bytes(), sesion.id, cfg.vida_sesion_minutos, condicion)

    audit.registrar(bd, "partida_abierta", sesion_id=sesion.id,
                    codigo=sesion.codigo, version_cliente=datos.version_cliente,
                    condicion=condicion)

    return RespuestaSesion(
        sesion_id=sesion.id, codigo=sesion.codigo, condicion=condicion,
        token=token, clave_firma=clave.hex(), expira_en=expira,
        ventana_firma_segundos=cfg.ventana_firma_segundos,
    )


# ---------------------------------------------------------------------------
@router.post("/sesiones/{sesion_id}/eventos", status_code=status.HTTP_202_ACCEPTED,
             summary="Registrar eventos de la partida")
def registrar_eventos(sesion_id: str, lote: LoteEventos, bd: BD, cfg: Cfg,
                      sesion: SesionAuth):
    """Recibe por lotes lo que va ocurriendo durante la partida."""
    coincide_ruta(sesion_id, sesion)

    if sesion.cerrada:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "La partida ya está cerrada y no admite más eventos.")

    if sesion.eventos_recibidos + len(lote.eventos) > cfg.limite_eventos_por_sesion:
        sesion.rechazos += 1
        audit.registrar(bd, "limite_eventos", sesion_id=sesion.id, severidad="alerta",
                        recibidos=sesion.eventos_recibidos)
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "Se superó el número de eventos por partida.")

    for e in lote.eventos:
        bd.add(EventoPartida(sesion_id=sesion.id, tipo=e.tipo,
                             transcurrido_ms=e.transcurrido_ms, datos=e.datos))
    sesion.eventos_recibidos += len(lote.eventos)
    return {"recibidos": len(lote.eventos), "acumulados": sesion.eventos_recibidos}


# ---------------------------------------------------------------------------
@router.post("/sesiones/{sesion_id}/cierre", response_model=RespuestaCierre,
             summary="Cerrar la partida con sus indicadores")
def cerrar_partida(sesion_id: str, datos: SolicitudCierre, bd: BD, sesion: SesionAuth):
    """Cierra la partida y guarda los indicadores que alimentan el estudio.

    Es idempotente: cerrar dos veces devuelve el cierre existente sin
    alterarlo, porque el cliente puede reintentar si se le cortó la red.
    """
    coincide_ruta(sesion_id, sesion)

    if sesion.cerrada:
        return RespuestaCierre(
            sesion_id=sesion.id, codigo=sesion.codigo, condicion=sesion.condicion,
            finalizada_en=como_utc(sesion.finalizada_en),
            duracion_ms=sesion.duracion_ms or 0,
            eventos_registrados=sesion.eventos_recibidos, nuevo=False,
        )

    sesion.finalizada_en = ahora()
    sesion.duracion_ms = datos.duracion_ms
    sesion.desenlace = datos.desenlace
    sesion.final = datos.final
    sesion.bateria_media = datos.bateria_media
    sesion.filtro_medio = datos.filtro_medio
    sesion.iluminacion_media = datos.iluminacion_media
    sesion.tiempo_oculto_ms = datos.tiempo_oculto_ms
    sesion.pct_agachado = datos.pct_agachado
    sesion.detecciones = datos.detecciones
    sesion.errores_hackeo = datos.errores_hackeo

    audit.registrar(bd, "partida_cerrada", sesion_id=sesion.id,
                    codigo=sesion.codigo, desenlace=datos.desenlace,
                    duracion_ms=datos.duracion_ms)

    return RespuestaCierre(
        sesion_id=sesion.id, codigo=sesion.codigo, condicion=sesion.condicion,
        finalizada_en=como_utc(sesion.finalizada_en), duracion_ms=datos.duracion_ms,
        eventos_registrados=sesion.eventos_recibidos, nuevo=True,
    )


# ---------------------------------------------------------------------------
@router.get("/sesiones/{sesion_id}", response_model=EstadoSesion,
            summary="Estado de la partida")
def estado(sesion_id: str, bd: BD, sesion: SesionAuth):
    coincide_ruta(sesion_id, sesion)
    transcurrido = None
    if sesion.cerrada:
        transcurrido = sesion.duracion_ms
    return EstadoSesion(
        sesion_id=sesion.id, codigo=sesion.codigo, condicion=sesion.condicion,
        cerrada=sesion.cerrada, eventos_registrados=sesion.eventos_recibidos,
        transcurrido_ms=transcurrido,
    )
