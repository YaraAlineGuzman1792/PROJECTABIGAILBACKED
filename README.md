# Project Abigail — Registro de Partidas

Servicio que recibe y conserva los datos de cada partida jugada del prototipo:
qué ocurrió durante el recorrido y con qué indicadores terminó. Es la fuente de
la que sale el archivo que se analiza en el estudio.

**Yara Aline Guzmán García** — Carné 0909-22-1792
Universidad Mariano Gálvez de Guatemala

---

## I. Qué hace

Una partida tiene tres momentos y el servicio los cubre en tres llamadas:

| Momento | Llamada | Qué guarda |
|---|---|---|
| Empieza | `POST /v1/sesiones` | Abre la partida, sortea la condición A o B y devuelve el código visible y la clave de firma |
| Se juega | `POST /v1/sesiones/{id}/eventos` | Lotes de eventos: estados de la IA, uso de herramientas, escondites, hackeos |
| Termina | `POST /v1/sesiones/{id}/cierre` | Duración, desenlace y los siete indicadores del estudio |

Y para la autora:

| Llamada | Para qué |
|---|---|
| `POST /v1/admin/acceso` | Obtener el token de administración |
| `GET /v1/admin/resumen` | Conteos y medias por condición |
| `GET /v1/admin/partidas` | Listado paginado |
| `GET /v1/admin/exportar.csv` | **Una fila por partida: el archivo del análisis** |
| `GET /v1/admin/eventos.csv` | Un renglón por evento |
| `GET /v1/admin/integridad` | Comprobar que la bitácora no fue alterada |

### El código de partida

Al abrir, el servicio asigna un código con el formato `PA-A-0001`. El juego lo
muestra en la pantalla final y la persona lo escribe en el cuestionario. Es lo
único que enlaza lo que respondió con lo que el juego registró: sin ese código,
la respuesta no entra en el análisis.

La letra intermedia es la condición experimental, que **sortea el servidor**.
Que no la elija el cliente es lo que sostiene la inferencia causal del estudio.

### Los siete indicadores

Se envían al cerrar la partida y son las columnas del CSV:

`bateria_media` · `filtro_medio` · `iluminacion_media` · `tiempo_oculto_ms` ·
`pct_agachado` · `detecciones` · `errores_hackeo`

---

## II. Seguridad

Lo que hay montado y por qué, en orden de lo que detiene primero:

| Capa | Qué impide |
|---|---|
| Límite de tasa por IP y por partida | Que alguien sature el servicio a fuerza de peticiones |
| Límite de tamaño de cuerpo (32 KB) | Que un cuerpo enorme agote la memoria antes de validarse |
| Firma HMAC-SHA256 por petición | Que se envíen datos sin pasar por el juego |
| Marca de tiempo con ventana de 120 s | Que se reutilice una petición capturada |
| Nonce de un solo uso | Que se repita una petición idéntica |
| Clave efímera por partida | Que el ejecutable lleve un secreto reutilizable dentro |
| Validación estricta con lista blanca | Que entren tipos de evento o campos inventados |
| Revocación tras 10 firmas inválidas | Que alguien pruebe firmas a ciegas |
| Argon2id y bloqueo tras 5 intentos | Que se adivine la contraseña de administración |
| Bitácora encadenada por hash | Que se altere o borre un registro sin que se note |
| Cabeceras de seguridad y CORS cerrado | Que el servicio se use desde una página ajena |

Dos cosas que conviene entender bien:

**La clave de firma no viaja en el ejecutable.** El servidor la entrega al abrir
la partida y vive sólo en memoria. Quien abra el `.exe` con un editor no
encuentra nada que reutilizar.

**Lo que se firma son los bytes exactos que se envían.** El cliente serializa el
JSON una vez, firma ese buffer y manda ese mismo buffer. Reconstruirlo antes de
enviarlo cambia un espacio y la firma deja de cuadrar.

### Qué NO protege

Decirlo también es parte del trabajo. Esto no defiende contra un ataque de
denegación distribuido con muchas máquinas: el límite de tasa es por instancia y
en memoria. Para eso va Cloudflare delante, que es gratis y se explica en la
guía de despliegue.

Y lo más importante para la defensa: **si el servicio se cae, la partida sigue**.
El cliente de Unreal registra el fallo y continúa. Los datos de esa sesión se
pierden, el juego no.

---

## III. Levantarlo en local

```bash
pip install -r requirements.txt
cp .env.example .env            # y rellenar CLAVE_MAESTRA y ADMIN_PASSWORD
uvicorn app.main:app --reload
```

Con `ENTORNO=desarrollo` la documentación interactiva queda en
`http://127.0.0.1:8000/docs`. En producción se desactiva sola.

Comprobar que todo responde, sin abrir Unreal:

```bash
python scripts/partida_de_prueba.py http://127.0.0.1:8000
```

Pruebas:

```bash
python -m pytest -q          # 30 pruebas
```

---

## IV. Subirlo a la nube

Ver **`docs/DESPLIEGUE.md`**. Hay dos caminos:

- **Render**, sólo con el navegador y gratis, usando `render.yaml`. Ojo: su base
  de datos gratuita se borra a los 30 días.
- **Fly.io**, unos tres dólares al mes, con SQLite sobre un volumen que no
  caduca. Es la opción que aguanta hasta la defensa sin sorpresas.

---

## V. Estructura

```
app/
├── main.py           arranque, cabeceras, límite de tasa
├── config.py         configuración desde el entorno
├── database.py       conexión; SQLite o PostgreSQL
├── models.py         partidas, eventos, nonces, bitácora, administración
├── schemas.py        validación de entrada y salida
├── deps.py           autenticación y verificación de firma
├── audit.py          bitácora encadenada por hash
├── routers/
│   ├── juego.py      lo que consume Unreal
│   └── admin.py      consulta y exportación
└── security/
    ├── cripto.py     HKDF, HMAC-SHA256, Argon2id
    └── tokens.py     emisión y verificación de tokens

scripts/
├── crear_admin.py          crea la cuenta de administración
└── partida_de_prueba.py    simula una partida completa

docs/
├── SEGURIDAD.md      el detalle de cada capa
└── DESPLIEGUE.md     cómo subirlo, paso a paso
```
