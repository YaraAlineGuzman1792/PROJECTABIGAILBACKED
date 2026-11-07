"""Configuración de la aplicación. Todo secreto se lee del entorno."""
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Config(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8",
                                      extra="ignore")

    # --- Entorno ---
    entorno: Literal["desarrollo", "pruebas", "produccion"] = "desarrollo"
    nombre_servicio: str = "Project Abigail — Registro de Partidas"
    version: str = "2.0.0"

    # --- Base de datos ---
    # SQLite por omisión: un archivo, sin servicio aparte. Para PostgreSQL
    # basta con definir DATABASE_URL; la plataforma suele inyectarla sola.
    database_url: str = "sqlite:///./datos/abigail.db"

    # --- Criptografía ---
    # Clave maestra para derivar las claves HMAC por partida y firmar los JWT.
    # Al menos 256 bits de entropía. NUNCA se versiona.
    clave_maestra: str = Field(default="", min_length=0)

    # Ventana de validez de la marca de tiempo en las peticiones firmadas.
    ventana_firma_segundos: int = 120
    # Vida útil del token de partida.
    vida_sesion_minutos: int = 180
    # Retención de nonces para detección de repetición.
    retencion_nonce_segundos: int = 300

    # --- Límites de tasa ---
    limite_sesiones_por_ip_hora: int = 20
    limite_peticiones_por_sesion_minuto: int = 120
    limite_peticiones_por_ip_minuto: int = 240
    limite_eventos_por_sesion: int = 5_000

    # --- Política de contenido ---
    max_cuerpo_bytes: int = 32 * 1024
    origenes_permitidos: list[str] = []

    # Cabecera de la que leer la IP real cuando hay un proxy delante
    # (Cloudflare: CF-Connecting-IP; Render y Fly: X-Forwarded-For).
    # Vacía si no hay proxy: de lo contrario cualquiera podría falsificarla.
    cabecera_ip_confiable: str = ""

    # --- Administración ---
    admin_usuario: str = "admin"
    # Una de las dos: el hash Argon2id ya calculado, o la contraseña en claro
    # que la aplicación convertirá en hash al arrancar.
    admin_password_hash: str = ""
    admin_password: str = ""

    @field_validator("clave_maestra")
    @classmethod
    def _validar_clave(cls, v: str, info) -> str:
        entorno = (info.data or {}).get("entorno", "desarrollo")
        # El umbral se mide en entropía, no en caracteres: 40 caracteres
        # bastan para los 256 bits que genera una plataforma en base64
        # (44 caracteres) y siguen rechazando una contraseña escrita a mano.
        if entorno == "produccion" and len(v) < 40:
            raise ValueError(
                "clave_maestra debe tener al menos 40 caracteres en producción. "
                "Genérala con: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        return v

    @property
    def es_produccion(self) -> bool:
        return self.entorno == "produccion"

    def clave_maestra_bytes(self) -> bytes:
        if self.clave_maestra:
            return self.clave_maestra.encode()
        if self.es_produccion:
            raise RuntimeError("clave_maestra ausente en producción")
        # Sólo para desarrollo y pruebas: determinista y claramente insegura.
        return b"clave-de-desarrollo-no-usar-en-produccion"


@lru_cache
def obtener_config() -> Config:
    return Config()
