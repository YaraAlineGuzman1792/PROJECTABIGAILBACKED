"""Pruebas de la capa de seguridad: firma, repetición, ventana y revocación."""
from __future__ import annotations

import json
import time

from app.security import cripto
from tests.conftest import ClienteJuego


def test_sesion_entrega_clave_y_token(juego):
    assert len(juego.clave) == 32
    assert juego.token.count(".") == 2


def test_peticion_sin_firma_es_rechazada(cliente, juego):
    r = cliente.post(f"/v1/sesiones/{juego.sesion_id}/eventos",
                     json={"eventos": [{"tipo": "prueba", "transcurrido_ms": 0}]},
                     headers={"Authorization": f"Bearer {juego.token}"})
    assert r.status_code == 400


def test_firma_invalida_es_rechazada(juego):
    r = juego.eventos({"tipo": "prueba", "transcurrido_ms": 0}) if False else None
    r = juego.post(f"/v1/sesiones/{juego.sesion_id}/eventos",
                   {"eventos": [{"tipo": "prueba", "transcurrido_ms": 0}]},
                   firma="0" * 64)
    assert r.status_code == 401
    assert "firma" in r.json()["detail"].lower()


def test_cuerpo_alterado_invalida_la_firma(cliente, juego):
    """Se firma un cuerpo y se envía otro: la firma deja de cuadrar."""
    ruta = f"/v1/sesiones/{juego.sesion_id}/eventos"
    original = json.dumps({"eventos": [{"tipo": "partida_iniciada", "transcurrido_ms": 10}]},
                          separators=(",", ":")).encode()
    alterado = json.dumps({"eventos": [{"tipo": "partida_iniciada", "transcurrido_ms": 999999}]},
                          separators=(",", ":")).encode()
    cabeceras = juego.cabeceras("POST", ruta, original)
    r = cliente.post(ruta, content=alterado, headers=cabeceras)
    assert r.status_code == 401


def test_repeticion_de_nonce_es_rechazada(juego):
    nonce = cripto.nuevo_nonce()
    carga = {"eventos": [{"tipo": "partida_iniciada", "transcurrido_ms": 10}]}
    primera = juego.post(f"/v1/sesiones/{juego.sesion_id}/eventos", carga, nonce=nonce)
    assert primera.status_code == 202
    segunda = juego.post(f"/v1/sesiones/{juego.sesion_id}/eventos", carga, nonce=nonce)
    assert segunda.status_code == 409


def test_marca_de_tiempo_antigua_es_rechazada(juego):
    vieja = str(int(time.time()) - 3600)
    r = juego.post(f"/v1/sesiones/{juego.sesion_id}/eventos",
                   {"eventos": [{"tipo": "partida_iniciada", "transcurrido_ms": 0}]}, marca=vieja)
    assert r.status_code == 400
    assert "ventana" in r.json()["detail"].lower()


def test_firma_de_una_ruta_no_sirve_en_otra(cliente, juego):
    """Una firma válida para /eventos no debe valer para /cierre."""
    ruta_a = f"/v1/sesiones/{juego.sesion_id}/eventos"
    ruta_b = f"/v1/sesiones/{juego.sesion_id}/cierre"
    cuerpo = json.dumps({"duracion_ms": 1000, "desenlace": "salida",
                         "bateria_media": 50.0, "filtro_medio": 50.0,
                         "iluminacion_media": 1.0, "tiempo_oculto_ms": 0,
                         "pct_agachado": 0.0, "detecciones": 0,
                         "errores_hackeo": 0}, separators=(",", ":")).encode()
    cabeceras = juego.cabeceras("POST", ruta_a, cuerpo)
    r = cliente.post(ruta_b, content=cuerpo, headers=cabeceras)
    assert r.status_code == 401


def test_token_de_otra_sesion_no_accede(cliente, juego):
    otro = ClienteJuego(cliente)
    r = otro.post(f"/v1/sesiones/{juego.sesion_id}/eventos",
                  {"eventos": [{"tipo": "partida_iniciada", "transcurrido_ms": 0}]})
    assert r.status_code == 403


def test_diez_firmas_invalidas_revocan_la_sesion(juego):
    for _ in range(10):
        juego.post(f"/v1/sesiones/{juego.sesion_id}/eventos",
                   {"eventos": [{"tipo": "partida_iniciada", "transcurrido_ms": 0}]}, firma="0" * 64)
    r = juego.eventos({"tipo": "partida_iniciada", "transcurrido_ms": 0})
    assert r.status_code == 401
    assert "revocada" in r.json()["detail"].lower()


def test_claves_de_sesiones_distintas_son_distintas(cliente):
    a, b = ClienteJuego(cliente), ClienteJuego(cliente)
    assert a.clave != b.clave


def test_cabeceras_de_seguridad_presentes(cliente):
    r = cliente.get("/salud")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]


def test_entrada_malformada_es_rechazada(juego):
    r = juego.post(f"/v1/sesiones/{juego.sesion_id}/eventos",
                   {"eventos": [{"tipo": "EN MAYÚSCULAS", "transcurrido_ms": -5}]})
    assert r.status_code == 422


def test_json_anidado_en_los_datos_es_rechazado(juego):
    r = juego.post(f"/v1/sesiones/{juego.sesion_id}/eventos",
                   {"eventos": [{"tipo": "documento_recogido", "transcurrido_ms": 30000,
                                 "datos": {"anidado": {"a": 1}}}]})
    assert r.status_code == 422


def test_campo_extra_es_rechazado(juego):
    r = juego.post(f"/v1/sesiones/{juego.sesion_id}/eventos",
                   {"eventos": [{"tipo": "escondite_usado", "transcurrido_ms": 10}],
                    "colado": "x"})
    assert r.status_code == 422
