"""Primitivas criptográficas: derivación de claves, firma HMAC y contraseñas.

El modelo de amenaza parte de un hecho incómodo: el cliente del juego se
distribuye a quien quiera descargarlo, de modo que cualquier secreto embebido
en él es público por definición. Por eso ningún secreto de larga vida viaja al
cliente. El servidor deriva una clave efímera por sesión, la entrega una sola
vez, y a partir de ahí exige que cada petición venga firmada con ella.

Esto no hace imposible el fraude —nada lo hace en un cliente no confiable—,
pero eleva el costo de forjar una petición desde «editar un JSON» hasta
«extraer la clave de sesión en memoria y reimplementar la firma», y deja
rastro de cada intento en la bitácora.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Final

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

ETIQUETA_HMAC: Final = b"project-abigail/clave-sesion-hmac/v1"
ETIQUETA_HUELLA: Final = b"project-abigail/huella-origen/v1"
ALGORITMO: Final = "sha256"


# ---------------------------------------------------------------------------
# Derivación de claves (HKDF, RFC 5869)
# ---------------------------------------------------------------------------
def _hkdf_extraer(sal: bytes, material: bytes) -> bytes:
    return hmac.new(sal, material, hashlib.sha256).digest()


def _hkdf_expandir(prk: bytes, info: bytes, longitud: int = 32) -> bytes:
    salida, bloque, contador = b"", b"", 1
    while len(salida) < longitud:
        bloque = hmac.new(prk, bloque + info + bytes([contador]), hashlib.sha256).digest()
        salida += bloque
        contador += 1
    return salida[:longitud]


def derivar_clave_sesion(clave_maestra: bytes, sesion_id: str) -> bytes:
    """Deriva la clave HMAC de una sesión a partir de la clave maestra.

    La clave de cada sesión es independiente: comprometer una no compromete
    ninguna otra, y el servidor no necesita almacenarlas porque puede volver a
    derivarlas en cualquier momento a partir del identificador de sesión.
    """
    prk = _hkdf_extraer(sesion_id.encode(), clave_maestra)
    return _hkdf_expandir(prk, ETIQUETA_HMAC, 32)


def huella_clave(clave: bytes) -> str:
    """Huella almacenable de una clave, para verificar sin guardar la clave."""
    return hashlib.sha256(ETIQUETA_HMAC + clave).hexdigest()


def huella_origen(clave_maestra: bytes, identificador: str) -> str:
    """Seudonimiza una dirección de red para poder limitar por origen.

    Permite contar peticiones por procedencia sin almacenar la dirección IP,
    que es un dato personal bajo varias legislaciones y que el estudio se
    comprometió a no recopilar.
    """
    return hmac.new(clave_maestra, ETIQUETA_HUELLA + identificador.encode(),
                    hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Firma de peticiones
# ---------------------------------------------------------------------------
def cadena_canonica(metodo: str, ruta: str, marca_tiempo: str,
                    nonce: str, cuerpo: bytes) -> bytes:
    """Construye la representación canónica que se firma.

    Se incluye el método y la ruta para impedir que una firma válida para un
    endpoint se reutilice en otro; la marca de tiempo y el nonce para acotar la
    repetición; y el hash del cuerpo para que ningún byte pueda alterarse.
    """
    hash_cuerpo = hashlib.sha256(cuerpo).hexdigest()
    partes = [metodo.upper(), ruta, marca_tiempo, nonce, hash_cuerpo]
    return "\n".join(partes).encode()


def firmar(clave: bytes, metodo: str, ruta: str, marca_tiempo: str,
           nonce: str, cuerpo: bytes) -> str:
    canonica = cadena_canonica(metodo, ruta, marca_tiempo, nonce, cuerpo)
    return hmac.new(clave, canonica, hashlib.sha256).hexdigest()


def verificar_firma(clave: bytes, firma_recibida: str, metodo: str, ruta: str,
                    marca_tiempo: str, nonce: str, cuerpo: bytes) -> bool:
    """Compara en tiempo constante para no filtrar información por temporización."""
    esperada = firmar(clave, metodo, ruta, marca_tiempo, nonce, cuerpo)
    return hmac.compare_digest(esperada, firma_recibida or "")


def nuevo_nonce() -> str:
    return secrets.token_hex(16)


# ---------------------------------------------------------------------------
# Contraseñas de administración
# ---------------------------------------------------------------------------
# Parámetros por encima del mínimo recomendado por OWASP para Argon2id.
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4,
                         hash_len=32, salt_len=16)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verificar_password(hash_guardado: str, password: str) -> bool:
    try:
        _hasher.verify(hash_guardado, password)
        return True
    except (VerifyMismatchError, InvalidHashError, Exception):
        return False


def requiere_rehash(hash_guardado: str) -> bool:
    try:
        return _hasher.check_needs_rehash(hash_guardado)
    except Exception:
        return True
