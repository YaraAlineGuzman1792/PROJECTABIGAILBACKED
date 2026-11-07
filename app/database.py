"""Conexión a la base de datos y sesión por petición."""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from .config import obtener_config
from .models import Base

_config = obtener_config()
_es_sqlite = _config.database_url.startswith("sqlite")

# Se fija el driver a mano en lugar de dejar que SQLAlchemy elija.
#
# Hacen falta las dos reescrituras. «postgres://» es el esquema antiguo que
# todavía entregan algunas plataformas y que SQLAlchemy ya no reconoce.
# «postgresql://» sí lo reconoce, pero desde SQLAlchemy 2.1 lo resuelve a
# psycopg 3, y el driver que se instala aquí es psycopg2: sin esta línea, un
# despliegue contra PostgreSQL muere al importar con «No module named
# psycopg». Es la forma que entrega Render.
_url = _config.database_url
for _viejo in ("postgres://", "postgresql://"):
    if _url.startswith(_viejo):
        _url = "postgresql+psycopg2://" + _url[len(_viejo):]
        break

if _es_sqlite:
    # El archivo vive en una carpeta propia para poder montarla como volumen.
    destino = _url.split("///", 1)[-1]
    if destino and destino != ":memory:":
        Path(destino).resolve().parent.mkdir(parents=True, exist_ok=True)

_opciones: dict = {"pool_pre_ping": True}
if _es_sqlite:
    _opciones["connect_args"] = {"check_same_thread": False, "timeout": 30}
else:
    _opciones.update(pool_size=5, max_overflow=5, pool_recycle=1800)

motor = create_engine(_url, **_opciones)


@event.listens_for(motor, "connect")
def _ajustes_sqlite(conexion, _registro):
    """SQLite necesita que se activen explícitamente varias garantías."""
    if not _es_sqlite:
        return
    cur = conexion.cursor()
    cur.execute("PRAGMA foreign_keys=ON")
    # WAL permite leer mientras se escribe y sobrevive mejor a un corte.
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.execute("PRAGMA busy_timeout=30000")
    cur.close()


FabricaSesion = sessionmaker(bind=motor, autoflush=False, autocommit=False, class_=Session)


def obtener_bd() -> Iterator[Session]:
    bd = FabricaSesion()
    try:
        yield bd
        bd.commit()
    except Exception:
        bd.rollback()
        raise
    finally:
        bd.close()


def crear_tablas() -> None:
    Base.metadata.create_all(bind=motor)
