"""Esquemas de entrada y salida. Toda entrada se valida de forma estricta."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_CLAVES_JSON = 24
MAX_LONGITUD_VALOR = 256

# Tipos de evento admitidos. Una lista blanca evita que el cliente invente
# categorías y ensucie la base con datos que el análisis no sabrá interpretar.
TIPOS_EVENTO = {
    "partida_iniciada", "ia_estado", "linterna_encendida", "bateria_agotada",
    "hackeo_iniciado", "hackeo_completado", "hackeo_fallido",
    "zona_toxica_entrada", "zona_toxica_salida", "filtro_agotado",
    "documento_recogido", "energia_restaurada", "escondite_usado",
    "jugador_detectado", "sector_completado", "partida_finalizada",
}


def _saneado(d: dict[str, Any], nombre: str) -> dict[str, Any]:
    """Acota el tamaño y la forma de los diccionarios libres.

    Sin este límite, un cliente podría enviar un objeto arbitrariamente grande
    o anidado y convertir la columna JSON en un vector de abuso.
    """
    if len(d) > MAX_CLAVES_JSON:
        raise ValueError(f"{nombre} admite como máximo {MAX_CLAVES_JSON} claves")
    for clave, valor in d.items():
        if not isinstance(clave, str) or len(clave) > 48:
            raise ValueError(f"clave inválida en {nombre}: {clave!r}")
        if isinstance(valor, (dict, list)):
            raise ValueError(f"{nombre} no admite estructuras anidadas (clave {clave!r})")
        if isinstance(valor, str) and len(valor) > MAX_LONGITUD_VALOR:
            raise ValueError(f"valor demasiado largo en {nombre}, clave {clave!r}")
    return d


# ---------------------------------------------------------------------------
class SolicitudSesion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version_cliente: str = Field(min_length=1, max_length=32,
                                 pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$")
    condicion: Literal["A", "B"] | None = Field(
        default=None,
        description="Rama experimental. Si se omite, el servidor la sortea, que es "
                    "lo correcto para el estudio: la asignación no debe depender del cliente.")


class RespuestaSesion(BaseModel):
    sesion_id: str
    codigo: str = Field(description="Código que se muestra en pantalla al terminar la "
                                    "partida, con el formato PA-A-0001.")
    condicion: str
    token: str
    clave_firma: str = Field(description="Clave HMAC de la sesión, en hexadecimal. "
                                         "Se entrega una sola vez y no se almacena en claro.")
    expira_en: datetime
    algoritmo_firma: str = "HMAC-SHA256"
    ventana_firma_segundos: int


# ---------------------------------------------------------------------------
class SolicitudEvento(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tipo: str = Field(min_length=1, max_length=48, pattern=r"^[a-z][a-z0-9_]*$")
    transcurrido_ms: int = Field(ge=0, le=86_400_000)
    datos: dict[str, Any] = Field(default_factory=dict)

    @field_validator("tipo")
    @classmethod
    def _tipo_conocido(cls, v: str) -> str:
        if v not in TIPOS_EVENTO:
            raise ValueError(f"tipo de evento no reconocido: {v!r}")
        return v

    @field_validator("datos")
    @classmethod
    def _v(cls, v): return _saneado(v, "datos")


class LoteEventos(BaseModel):
    model_config = ConfigDict(extra="forbid")
    eventos: list[SolicitudEvento] = Field(min_length=1, max_length=50)


# ---------------------------------------------------------------------------
class SolicitudCierre(BaseModel):
    """Indicadores finales de la partida, los que alimentan el estudio."""
    model_config = ConfigDict(extra="forbid")

    duracion_ms: int = Field(ge=0, le=86_400_000)
    desenlace: Literal["salida", "muerte", "abandono"]
    final: Literal["A", "B"] | None = None

    bateria_media: float = Field(ge=0, le=100)
    filtro_medio: float = Field(ge=0, le=100)
    iluminacion_media: float = Field(ge=0, le=10_000)
    tiempo_oculto_ms: int = Field(ge=0, le=86_400_000)
    pct_agachado: float = Field(ge=0, le=100)
    detecciones: int = Field(ge=0, le=10_000)
    errores_hackeo: int = Field(ge=0, le=10_000)


class RespuestaCierre(BaseModel):
    sesion_id: str
    codigo: str
    condicion: str
    finalizada_en: datetime
    duracion_ms: int
    eventos_registrados: int
    nuevo: bool = Field(description="Falso si la partida ya estaba cerrada.")


# ---------------------------------------------------------------------------
class EstadoSesion(BaseModel):
    sesion_id: str
    codigo: str
    condicion: str
    cerrada: bool
    eventos_registrados: int
    transcurrido_ms: int | None = None


class PartidaResumen(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    codigo: str
    condicion: str
    creada_en: datetime
    finalizada_en: datetime | None
    duracion_ms: int | None
    desenlace: str | None
    eventos_recibidos: int
    bateria_media: float | None
    filtro_medio: float | None
    tiempo_oculto_ms: int | None
    pct_agachado: float | None
    detecciones: int | None
    errores_hackeo: int | None


class PaginaPartidas(BaseModel):
    total: int
    pagina: int
    por_pagina: int
    partidas: list[PartidaResumen]


# ---------------------------------------------------------------------------
class SolicitudAcceso(BaseModel):
    model_config = ConfigDict(extra="forbid")
    usuario: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=256)


class RespuestaAcceso(BaseModel):
    token: str
    expira_en_minutos: int


class EstadoIntegridad(BaseModel):
    cadena_intacta: bool
    primera_entrada_corrupta: int | None = None
    total_entradas: int


class Salud(BaseModel):
    estado: str
    version: str
    entorno: str
