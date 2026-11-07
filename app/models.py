"""Modelo de datos del registro de partidas.

Una «sesión» es una partida: se abre al empezar a jugar, acumula eventos
mientras se juega y se cierra con los indicadores que alimentan el estudio.

SQLite por omisión; PostgreSQL si se define DATABASE_URL.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, CheckConstraint, DateTime, Float, ForeignKey, Index, Integer,
    JSON, String, func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def ahora() -> datetime:
    return datetime.now(timezone.utc)


def nuevo_id() -> str:
    return str(uuid.uuid4())


def como_utc(valor: datetime | None) -> datetime | None:
    """Normaliza a UTC con zona horaria.

    Dos casos distintos, y hacen falta los dos:

    SQLite no conserva la zona horaria, de modo que los valores leídos de la
    base vuelven «naive». Compararlos con datetimes conscientes de zona lanza
    TypeError, así que se les asigna UTC, que es como se guardaron.

    PostgreSQL sí la conserva, pero devuelve el valor en la zona de la sesión,
    no en UTC: el mismo instante llega como «13:00-06:00» en vez de
    «19:00+00:00». Son iguales al comparar, pero su isoformat() no lo es, y la
    bitácora encadenada firma precisamente esa cadena. Sin convertir, la
    verificación de integridad falla en cuanto se despliega contra PostgreSQL.
    """
    if valor is None:
        return None
    if valor.tzinfo is None:
        return valor.replace(tzinfo=timezone.utc)
    return valor.astimezone(timezone.utc)


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
class Sesion(Base):
    """Una partida jugada.

    No guarda ningún dato que identifique a la persona: ni nombre, ni correo,
    ni dirección IP en claro. El origen se almacena como huella derivada, sólo
    para poder limitar el abuso.
    """
    __tablename__ = "sesiones"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=nuevo_id)
    codigo: Mapped[str] = mapped_column(String(16), nullable=False, unique=True)

    creada_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=ahora, nullable=False)
    expira_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version_cliente: Mapped[str] = mapped_column(String(32), nullable=False)

    # Rama experimental del estudio: A con oscuridad dinámica y recursos
    # limitados, B con iluminación estática y recursos amplios.
    condicion: Mapped[str] = mapped_column(String(1), nullable=False)

    huella_clave: Mapped[str] = mapped_column(String(64), nullable=False)
    huella_origen: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    revocada: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    motivo_revocacion: Mapped[str | None] = mapped_column(String(160))

    peticiones: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    eventos_recibidos: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rechazos: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # --- Cierre de la partida -------------------------------------------
    finalizada_en: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duracion_ms: Mapped[int | None] = mapped_column(Integer)
    desenlace: Mapped[str | None] = mapped_column(String(16))   # salida | muerte | abandono
    final: Mapped[str | None] = mapped_column(String(1))        # A o B, por la ramificación

    # --- Indicadores del estudio ----------------------------------------
    bateria_media: Mapped[float | None] = mapped_column(Float)
    filtro_medio: Mapped[float | None] = mapped_column(Float)
    iluminacion_media: Mapped[float | None] = mapped_column(Float)
    tiempo_oculto_ms: Mapped[int | None] = mapped_column(Integer)
    pct_agachado: Mapped[float | None] = mapped_column(Float)
    detecciones: Mapped[int | None] = mapped_column(Integer)
    errores_hackeo: Mapped[int | None] = mapped_column(Integer)

    eventos: Mapped[list[EventoPartida]] = relationship(
        back_populates="sesion", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint("condicion IN ('A','B')", name="ck_sesiones_condicion"),
        CheckConstraint("peticiones >= 0", name="ck_sesiones_peticiones"),
        Index("ix_sesiones_creada", "creada_en"),
        Index("ix_sesiones_origen_creada", "huella_origen", "creada_en"),
        Index("ix_sesiones_finalizada", "finalizada_en"),
    )

    def vigente(self) -> bool:
        """La partida admite peticiones: ni revocada ni expirada."""
        return not self.revocada and como_utc(self.expira_en) > ahora()

    @property
    def cerrada(self) -> bool:
        return self.finalizada_en is not None


# ---------------------------------------------------------------------------
class EventoPartida(Base):
    """Un hecho ocurrido durante la partida, con el momento en que ocurrió."""
    __tablename__ = "eventos_partida"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=nuevo_id)
    sesion_id: Mapped[str] = mapped_column(
        ForeignKey("sesiones.id", ondelete="CASCADE"), nullable=False)
    tipo: Mapped[str] = mapped_column(String(48), nullable=False)
    registrado_en: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=ahora, nullable=False)
    transcurrido_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    datos: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    sesion: Mapped[Sesion] = relationship(back_populates="eventos")

    __table_args__ = (
        Index("ix_eventos_sesion_tipo", "sesion_id", "tipo"),
        CheckConstraint("transcurrido_ms >= 0", name="ck_eventos_transcurrido"),
    )


# ---------------------------------------------------------------------------
class Nonce(Base):
    """Nonces consumidos, para rechazar peticiones repetidas."""
    __tablename__ = "nonces"

    valor: Mapped[str] = mapped_column(String(64), primary_key=True)
    sesion_id: Mapped[str] = mapped_column(String(36), nullable=False)
    visto_en: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=ahora, nullable=False)

    __table_args__ = (Index("ix_nonces_visto", "visto_en"),)


# ---------------------------------------------------------------------------
class EntradaBitacora(Base):
    """Bitácora de auditoría encadenada por hash: sólo se añade, nunca se edita.

    Cada entrada incorpora el hash de la anterior, de modo que alterar o
    eliminar cualquier registro rompe la cadena de forma detectable.
    """
    __tablename__ = "bitacora"

    secuencia: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ocurrido_en: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=ahora, nullable=False)
    evento: Mapped[str] = mapped_column(String(64), nullable=False)
    sesion_id: Mapped[str | None] = mapped_column(String(36))
    severidad: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    detalle: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    hash_previo: Mapped[str] = mapped_column(String(64), nullable=False)
    hash_entrada: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        CheckConstraint("severidad IN ('info','alerta','critico')", name="ck_bitacora_severidad"),
        Index("ix_bitacora_evento", "evento"),
        Index("ix_bitacora_ocurrido", "ocurrido_en"),
    )


# ---------------------------------------------------------------------------
class Administrador(Base):
    """Cuenta de administración para consultar y exportar los datos."""
    __tablename__ = "administradores"

    usuario: Mapped[str] = mapped_column(String(64), primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    creado_en: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=ahora, nullable=False)
    ultimo_acceso: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    intentos_fallidos: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    bloqueado_hasta: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
