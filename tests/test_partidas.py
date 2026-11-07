"""Pruebas del ciclo de vida de una partida."""
from __future__ import annotations

from .conftest import ClienteJuego, ev


def test_abrir_devuelve_codigo_legible(juego):
    assert juego.codigo.startswith("PA-A-")
    assert len(juego.codigo) == 9          # PA-A-0001
    assert juego.condicion == "A"


def test_codigos_corren_por_condicion(cliente):
    a1 = ClienteJuego(cliente, "A")
    a2 = ClienteJuego(cliente, "A")
    b1 = ClienteJuego(cliente, "B")
    assert a1.codigo == "PA-A-0001"
    assert a2.codigo == "PA-A-0002"
    assert b1.codigo == "PA-B-0001"


def test_el_servidor_sortea_la_condicion_si_no_se_indica(cliente):
    condiciones = {ClienteJuego(cliente, None).condicion for _ in range(12)}
    # Con doce partidas es prácticamente imposible que salga una sola rama.
    assert condiciones == {"A", "B"}


def test_registrar_eventos_acumula(juego):
    r = juego.eventos(ev("partida_iniciada", 0),
                      ev("escondite_usado", 4_000),
                      ev("ia_estado", 5_000, estado="Investigar"))
    assert r.status_code == 202
    assert r.json() == {"recibidos": 3, "acumulados": 3}

    r = juego.eventos(ev("documento_recogido", 9_000, id="D-01"))
    assert r.json()["acumulados"] == 4


def test_rechaza_tipo_de_evento_desconocido(juego):
    r = juego.eventos(ev("bailar_cumbia", 1_000))
    assert r.status_code == 422


def test_cierre_guarda_los_indicadores(juego):
    juego.eventos(ev("partida_iniciada", 0))
    r = juego.cerrar(duracion_ms=840_000, pct_agachado=71.5, errores_hackeo=4)
    assert r.status_code == 200
    cuerpo = r.json()
    assert cuerpo["nuevo"] is True
    assert cuerpo["codigo"] == juego.codigo
    assert cuerpo["duracion_ms"] == 840_000
    assert cuerpo["eventos_registrados"] == 1


def test_cierre_es_idempotente(juego):
    primero = juego.cerrar(duracion_ms=600_000)
    segundo = juego.cerrar(duracion_ms=999_999)
    assert primero.json()["nuevo"] is True
    assert segundo.json()["nuevo"] is False
    # El segundo intento no debe sobrescribir lo ya registrado.
    assert segundo.json()["duracion_ms"] == 600_000


def test_no_se_admiten_eventos_tras_el_cierre(juego):
    juego.cerrar()
    r = juego.eventos(ev("documento_recogido", 10_000, id="D-02"))
    assert r.status_code == 409


def test_indicadores_fuera_de_rango_se_rechazan(juego):
    assert juego.cerrar(pct_agachado=140).status_code == 422
    assert juego.cerrar(bateria_media=-1).status_code == 422
    assert juego.cerrar(desenlace="teletransporte").status_code == 422


def test_estado_refleja_el_cierre(juego):
    assert juego.estado().json()["cerrada"] is False
    juego.cerrar()
    cuerpo = juego.estado().json()
    assert cuerpo["cerrada"] is True
    assert cuerpo["codigo"] == juego.codigo


# --------------------------------------------------------------- administración
def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_exportacion_csv_incluye_la_partida(cliente, token_admin):
    j = ClienteJuego(cliente, "B")
    j.eventos(ev("partida_iniciada", 0))
    j.cerrar(duracion_ms=500_000, detecciones=7)

    r = cliente.get("/v1/admin/exportar.csv", headers=_auth(token_admin))
    assert r.status_code == 200
    texto = r.text
    assert "codigo,condicion,creada_en" in texto
    assert j.codigo in texto
    assert ",7," in texto          # detecciones


def test_exportacion_omite_las_partidas_abiertas(cliente, token_admin):
    abierta = ClienteJuego(cliente, "A")
    r = cliente.get("/v1/admin/exportar.csv", headers=_auth(token_admin))
    assert abierta.codigo not in r.text


def test_resumen_cuenta_por_condicion(cliente, token_admin):
    ClienteJuego(cliente, "A").cerrar()
    ClienteJuego(cliente, "B").cerrar()
    ClienteJuego(cliente, "B")

    r = cliente.get("/v1/admin/resumen", headers=_auth(token_admin))
    assert r.status_code == 200
    datos = r.json()
    assert datos["partidas"]["total"] == 3
    assert datos["partidas"]["por_condicion"] == {"A": 1, "B": 2}
    assert datos["partidas"]["cerradas_por_condicion"] == {"A": 1, "B": 1}


def test_listado_pagina_y_filtra(cliente, token_admin):
    for _ in range(3):
        ClienteJuego(cliente, "A").cerrar()
    ClienteJuego(cliente, "B").cerrar()

    r = cliente.get("/v1/admin/partidas?condicion=A&por_pagina=2",
                    headers=_auth(token_admin))
    datos = r.json()
    assert datos["total"] == 3
    assert len(datos["partidas"]) == 2


def test_administracion_exige_token(cliente):
    assert cliente.get("/v1/admin/exportar.csv").status_code in (401, 403)
    assert cliente.get("/v1/admin/resumen").status_code in (401, 403)


def test_bitacora_intacta_tras_operar(cliente, token_admin):
    ClienteJuego(cliente, "A").cerrar()
    r = cliente.get("/v1/admin/integridad", headers=_auth(token_admin))
    assert r.status_code == 200
    assert r.json()["cadena_intacta"] is True
