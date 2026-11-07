"""Endpoints de administración: acceso, consulta, exportación e integridad."""
from __future__ import annotations

import csv
import io
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select

from .. import audit
from ..deps import BD, Cfg, admin_autenticado
from ..models import (
    Administrador, EntradaBitacora, EventoPartida, Sesion, ahora, como_utc,
)
from ..schemas import (
    EstadoIntegridad, PaginaPartidas, PartidaResumen, RespuestaAcceso,
    SolicitudAcceso,
)
from ..security import cripto, tokens

router = APIRouter(prefix="/v1/admin", tags=["administración"])
Admin = Annotated[Administrador, Depends(admin_autenticado)]

MAX_INTENTOS = 5
BLOQUEO_MINUTOS = 15


@router.post("/acceso", response_model=RespuestaAcceso, summary="Iniciar sesión")
def acceso(datos: SolicitudAcceso, bd: BD, cfg: Cfg):
    admin = bd.get(Administrador, datos.usuario)

    # Se verifica siempre contra un hash, exista o no la cuenta, para que el
    # tiempo de respuesta no revele qué usuarios están registrados.
    hash_referencia = admin.password_hash if admin else cripto.hash_password("inexistente")

    if admin and admin.bloqueado_hasta:
        if como_utc(admin.bloqueado_hasta) > ahora():
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                                "La cuenta está bloqueada temporalmente.")

    if not cripto.verificar_password(hash_referencia, datos.password) or admin is None:
        if admin:
            admin.intentos_fallidos += 1
            if admin.intentos_fallidos >= MAX_INTENTOS:
                admin.bloqueado_hasta = ahora() + timedelta(minutes=BLOQUEO_MINUTOS)
                audit.registrar(bd, "admin_bloqueado", severidad="critico",
                                usuario=datos.usuario)
        audit.registrar(bd, "admin_acceso_fallido", severidad="alerta",
                        usuario=datos.usuario)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenciales inválidas.")

    admin.intentos_fallidos = 0
    admin.bloqueado_hasta = None
    admin.ultimo_acceso = ahora()
    if cripto.requiere_rehash(admin.password_hash):
        admin.password_hash = cripto.hash_password(datos.password)

    audit.registrar(bd, "admin_acceso", usuario=admin.usuario)
    return RespuestaAcceso(
        token=tokens.emitir_token_admin(cfg.clave_maestra_bytes(), admin.usuario),
        expira_en_minutos=30)


@router.get("/integridad", response_model=EstadoIntegridad,
            summary="Verificar la cadena de la bitácora")
def integridad(bd: BD, _: Admin):
    intacta, corrupta = audit.verificar_cadena(bd)
    total = bd.execute(select(func.count()).select_from(EntradaBitacora)).scalar_one()
    return EstadoIntegridad(cadena_intacta=intacta, primera_entrada_corrupta=corrupta,
                            total_entradas=total)


@router.get("/resumen", summary="Resumen agregado para el estudio")
def resumen(bd: BD, _: Admin):
    """Conteos agregados. No expone ningún dato individual identificable."""
    por_condicion = dict(bd.execute(
        select(Sesion.condicion, func.count()).group_by(Sesion.condicion)
    ).all())

    cerradas = dict(bd.execute(
        select(Sesion.condicion, func.count())
        .where(Sesion.finalizada_en.is_not(None)).group_by(Sesion.condicion)
    ).all())

    medias = bd.execute(
        select(Sesion.condicion,
               func.avg(Sesion.bateria_media), func.avg(Sesion.filtro_medio),
               func.avg(Sesion.pct_agachado), func.avg(Sesion.errores_hackeo),
               func.avg(Sesion.duracion_ms))
        .where(Sesion.finalizada_en.is_not(None)).group_by(Sesion.condicion)
    ).all()

    por_tipo = dict(bd.execute(
        select(EventoPartida.tipo, func.count()).group_by(EventoPartida.tipo)
    ).all())

    alertas = dict(bd.execute(
        select(EntradaBitacora.evento, func.count())
        .where(EntradaBitacora.severidad.in_(("alerta", "critico")))
        .group_by(EntradaBitacora.evento)
    ).all())

    return {
        "partidas": {
            "total": sum(por_condicion.values()),
            "por_condicion": por_condicion,
            "cerradas_por_condicion": cerradas,
        },
        "medias_por_condicion": [
            {"condicion": c, "bateria_media": b, "filtro_medio": f,
             "pct_agachado": p, "errores_hackeo": e, "duracion_ms": d}
            for c, b, f, p, e, d in medias
        ],
        "eventos": {"total": sum(por_tipo.values()), "por_tipo": por_tipo},
        "incidencias_seguridad": alertas,
    }


@router.get("/partidas", response_model=PaginaPartidas, summary="Listado de partidas")
def partidas(bd: BD, _: Admin,
             pagina: int = Query(1, ge=1),
             por_pagina: int = Query(50, ge=1, le=200),
             condicion: str | None = Query(None, pattern=r"^[AB]$"),
             solo_cerradas: bool = False):
    consulta = select(Sesion)
    if condicion:
        consulta = consulta.where(Sesion.condicion == condicion)
    if solo_cerradas:
        consulta = consulta.where(Sesion.finalizada_en.is_not(None))

    total = bd.execute(
        select(func.count()).select_from(consulta.subquery())).scalar_one()
    filas = bd.execute(
        consulta.order_by(Sesion.creada_en.desc())
        .offset((pagina - 1) * por_pagina).limit(por_pagina)
    ).scalars().all()

    return PaginaPartidas(total=total, pagina=pagina, por_pagina=por_pagina,
                          partidas=[PartidaResumen.model_validate(f) for f in filas])


COLUMNAS = [
    "codigo", "condicion", "creada_en", "finalizada_en", "duracion_ms",
    "desenlace", "final", "eventos_recibidos", "bateria_media", "filtro_medio",
    "iluminacion_media", "tiempo_oculto_ms", "pct_agachado", "detecciones",
    "errores_hackeo",
]


@router.get("/exportar.csv", summary="Exportar las partidas en CSV")
def exportar(bd: BD, _: Admin, solo_cerradas: bool = True):
    """Devuelve la base lista para el análisis estadístico.

    Una fila por partida, una columna por indicador. Es el archivo que se
    cruza con las respuestas del cuestionario usando el código de partida.
    """
    consulta = select(Sesion).order_by(Sesion.creada_en)
    if solo_cerradas:
        consulta = consulta.where(Sesion.finalizada_en.is_not(None))

    def filas():
        memoria = io.StringIO()
        escritor = csv.writer(memoria)
        escritor.writerow(COLUMNAS)
        yield memoria.getvalue()
        memoria.seek(0); memoria.truncate(0)

        for s in bd.execute(consulta).scalars().yield_per(200):
            escritor.writerow([
                s.codigo, s.condicion,
                como_utc(s.creada_en).isoformat(),
                como_utc(s.finalizada_en).isoformat() if s.finalizada_en else "",
                s.duracion_ms if s.duracion_ms is not None else "",
                s.desenlace or "", s.final or "", s.eventos_recibidos,
                s.bateria_media if s.bateria_media is not None else "",
                s.filtro_medio if s.filtro_medio is not None else "",
                s.iluminacion_media if s.iluminacion_media is not None else "",
                s.tiempo_oculto_ms if s.tiempo_oculto_ms is not None else "",
                s.pct_agachado if s.pct_agachado is not None else "",
                s.detecciones if s.detecciones is not None else "",
                s.errores_hackeo if s.errores_hackeo is not None else "",
            ])
            yield memoria.getvalue()
            memoria.seek(0); memoria.truncate(0)

    marca = ahora().strftime("%Y%m%d-%H%M")
    return StreamingResponse(
        filas(), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition":
                 f'attachment; filename="partidas-abigail-{marca}.csv"'},
    )


@router.get("/eventos.csv", summary="Exportar los eventos en CSV")
def exportar_eventos(bd: BD, _: Admin):
    """Un renglón por evento, enlazado a la partida por su código."""
    consulta = (select(EventoPartida, Sesion.codigo, Sesion.condicion)
                .join(Sesion, Sesion.id == EventoPartida.sesion_id)
                .order_by(Sesion.creada_en, EventoPartida.transcurrido_ms))

    def filas():
        memoria = io.StringIO()
        escritor = csv.writer(memoria)
        escritor.writerow(["codigo_partida", "condicion", "tipo",
                           "transcurrido_ms", "datos"])
        yield memoria.getvalue()
        memoria.seek(0); memoria.truncate(0)
        for evento, codigo, condicion in bd.execute(consulta).yield_per(500):
            escritor.writerow([codigo, condicion, evento.tipo,
                               evento.transcurrido_ms,
                               ";".join(f"{k}={v}" for k, v in evento.datos.items())])
            yield memoria.getvalue()
            memoria.seek(0); memoria.truncate(0)

    marca = ahora().strftime("%Y%m%d-%H%M")
    return StreamingResponse(
        filas(), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition":
                 f'attachment; filename="eventos-abigail-{marca}.csv"'},
    )


@router.post("/sesiones/{sesion_id}/revocar", summary="Revocar una partida")
def revocar(sesion_id: str, bd: BD, admin: Admin, motivo: str = "Revocación manual."):
    sesion = bd.get(Sesion, sesion_id)
    if sesion is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "La partida no existe.")
    sesion.revocada = True
    sesion.motivo_revocacion = motivo[:160]
    audit.registrar(bd, "sesion_revocada", sesion_id=sesion_id, severidad="critico",
                    por=admin.usuario, motivo=motivo[:160])
    return {"sesion_id": sesion_id, "revocada": True}
