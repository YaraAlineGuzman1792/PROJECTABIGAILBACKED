"""Infraestructura de pruebas: base de datos efímera y cliente que firma."""
from __future__ import annotations

import json
import os
import time

import pytest

os.environ["ENTORNO"] = "pruebas"
os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"
os.environ["CLAVE_MAESTRA"] = "a" * 96
os.environ["ADMIN_USUARIO"] = "admin"
os.environ["ADMIN_PASSWORD"] = "clave-de-pruebas-larga"

from fastapi.testclient import TestClient            # noqa: E402
from sqlalchemy import create_engine                 # noqa: E402
from sqlalchemy.orm import sessionmaker              # noqa: E402
from sqlalchemy.pool import StaticPool               # noqa: E402

from app import database                             # noqa: E402
from app.models import Base                          # noqa: E402
from app.security import cripto                      # noqa: E402

# Una única conexión compartida para que :memory: persista entre sesiones.
database.motor = create_engine(
    "sqlite+pysqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
database.FabricaSesion = sessionmaker(bind=database.motor, autoflush=False,
                                      autocommit=False)

from app.main import app                             # noqa: E402


@pytest.fixture(scope="function")
def cliente():
    Base.metadata.drop_all(bind=database.motor)
    Base.metadata.create_all(bind=database.motor)
    with TestClient(app) as c:
        yield c


class ClienteJuego:
    """Simula al cliente de Unreal: abre la partida y firma cada petición."""

    def __init__(self, cliente: TestClient, condicion: str | None = "A"):
        self.http = cliente
        carga = {"version_cliente": "1.0.0"}
        if condicion is not None:
            carga["condicion"] = condicion
        r = cliente.post("/v1/sesiones", json=carga)
        assert r.status_code == 201, r.text
        datos = r.json()
        self.sesion_id = datos["sesion_id"]
        self.codigo = datos["codigo"]
        self.condicion = datos["condicion"]
        self.token = datos["token"]
        self.clave = bytes.fromhex(datos["clave_firma"])

    def cabeceras(self, metodo: str, ruta: str, cuerpo: bytes,
                  marca: str | None = None, nonce: str | None = None,
                  firma: str | None = None) -> dict:
        marca = marca or str(int(time.time()))
        nonce = nonce or cripto.nuevo_nonce()
        firma = firma or cripto.firmar(self.clave, metodo, ruta, marca, nonce, cuerpo)
        return {
            "Authorization": f"Bearer {self.token}",
            "X-Marca-Tiempo": marca,
            "X-Nonce": nonce,
            "X-Firma": firma,
            "Content-Type": "application/json",
        }

    def post(self, ruta: str, carga: dict, **kw):
        cuerpo = json.dumps(carga, separators=(",", ":")).encode()
        return self.http.post(ruta, content=cuerpo,
                              headers=self.cabeceras("POST", ruta, cuerpo, **kw))

    def get(self, ruta: str, **kw):
        return self.http.get(ruta, headers=self.cabeceras("GET", ruta, b"", **kw))

    # --- atajos de dominio ---
    def eventos(self, *eventos: dict):
        return self.post(f"/v1/sesiones/{self.sesion_id}/eventos",
                         {"eventos": list(eventos)})

    def cerrar(self, **campos):
        carga = {
            "duracion_ms": 720_000, "desenlace": "salida", "final": "A",
            "bateria_media": 42.5, "filtro_medio": 61.0,
            "iluminacion_media": 3.2, "tiempo_oculto_ms": 95_000,
            "pct_agachado": 58.0, "detecciones": 3, "errores_hackeo": 2,
        }
        carga.update(campos)
        return self.post(f"/v1/sesiones/{self.sesion_id}/cierre", carga)

    def estado(self):
        return self.get(f"/v1/sesiones/{self.sesion_id}")


@pytest.fixture
def juego(cliente):
    return ClienteJuego(cliente)


@pytest.fixture
def token_admin(cliente):
    r = cliente.post("/v1/admin/acceso",
                     json={"usuario": "admin", "password": "clave-de-pruebas-larga"})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def ev(tipo: str, ms: int, **datos) -> dict:
    return {"tipo": tipo, "transcurrido_ms": ms, "datos": datos}
