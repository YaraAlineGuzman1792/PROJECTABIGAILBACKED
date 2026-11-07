#!/usr/bin/env python3
"""Simula una partida completa contra el servicio, firmando como lo hace el juego.

Sirve para comprobar que un despliegue funciona de extremo a extremo sin
tener que abrir Unreal.

    python scripts/partida_de_prueba.py https://abigail-partidas.onrender.com
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sys
import time
import urllib.error
import urllib.request


def firmar(clave: bytes, metodo: str, ruta: str, marca: str, nonce: str,
           cuerpo: bytes) -> str:
    canonica = "\n".join([
        metodo.upper(), ruta, marca, nonce, hashlib.sha256(cuerpo).hexdigest(),
    ]).encode()
    return hmac.new(clave, canonica, hashlib.sha256).hexdigest()


def pedir(url: str, ruta: str, carga: dict | None = None, *,
          metodo: str = "POST", token: str | None = None,
          clave: bytes | None = None) -> dict:
    cuerpo = json.dumps(carga, separators=(",", ":")).encode() if carga is not None else b""
    cabeceras = {"Content-Type": "application/json"}
    if token and clave:
        marca = str(int(time.time()))
        nonce = secrets.token_hex(16)
        cabeceras.update({
            "Authorization": f"Bearer {token}",
            "X-Marca-Tiempo": marca,
            "X-Nonce": nonce,
            "X-Firma": firmar(clave, metodo, ruta, marca, nonce, cuerpo),
        })
    peticion = urllib.request.Request(url + ruta, data=cuerpo or None,
                                      headers=cabeceras, method=metodo)
    try:
        with urllib.request.urlopen(peticion, timeout=30) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        detalle = e.read().decode(errors="replace")
        raise SystemExit(f"  FALLÓ {metodo} {ruta} → {e.code}\n  {detalle}") from None


def main() -> int:
    url = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000").rstrip("/")
    print(f"Servicio: {url}")

    salud = pedir(url, "/salud", metodo="GET")
    print(f"  salud ......... {salud['estado']} · versión {salud['version']}")

    sesion = pedir(url, "/v1/sesiones", {"version_cliente": "1.0.0"})
    sid, token = sesion["sesion_id"], sesion["token"]
    clave = bytes.fromhex(sesion["clave_firma"])
    print(f"  partida ....... {sesion['codigo']} · condición {sesion['condicion']}")

    eventos = [
        {"tipo": "partida_iniciada", "transcurrido_ms": 0, "datos": {}},
        {"tipo": "ia_estado", "transcurrido_ms": 31_000, "datos": {"estado": "Investigar"}},
        {"tipo": "escondite_usado", "transcurrido_ms": 36_000, "datos": {}},
        {"tipo": "ia_estado", "transcurrido_ms": 58_000, "datos": {"estado": "Patrullar"}},
        {"tipo": "hackeo_completado", "transcurrido_ms": 95_000, "datos": {"terminal": "T-02"}},
        {"tipo": "documento_recogido", "transcurrido_ms": 140_000, "datos": {"id": "D-03"}},
        {"tipo": "bateria_agotada", "transcurrido_ms": 210_000, "datos": {}},
        {"tipo": "partida_finalizada", "transcurrido_ms": 300_000, "datos": {"final": "A"}},
    ]
    r = pedir(url, f"/v1/sesiones/{sid}/eventos", {"eventos": eventos},
              token=token, clave=clave)
    print(f"  eventos ....... {r['recibidos']} enviados, {r['acumulados']} acumulados")

    cierre = pedir(url, f"/v1/sesiones/{sid}/cierre", {
        "duracion_ms": 300_000, "desenlace": "salida", "final": "A",
        "bateria_media": 38.4, "filtro_medio": 55.1, "iluminacion_media": 2.7,
        "tiempo_oculto_ms": 64_000, "pct_agachado": 62.3,
        "detecciones": 2, "errores_hackeo": 1,
    }, token=token, clave=clave)
    print(f"  cierre ........ {cierre['codigo']} · {cierre['duracion_ms']} ms")

    print("\nLa cadena completa funciona. El código de la partida es "
          f"{cierre['codigo']}: es el que se muestra en pantalla al terminar.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
