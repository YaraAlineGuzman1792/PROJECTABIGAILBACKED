# Cómo subir el servicio a la nube

Dos caminos. El primero no necesita instalar nada y es gratis; el segundo
cuesta unos tres dólares al mes y no tiene fecha de caducidad.

---

## Antes de empezar: subir el código a GitHub

Los dos caminos parten de un repositorio.

1. Entra a **github.com/new**.
2. Nombre: `PG2-Abigail`. Visibilidad: **Private** si prefieres, los dos
   servicios funcionan igual.
3. **Create repository**.
4. En la página del repositorio vacío, pulsa **uploading an existing file**.
5. Arrastra **el contenido descomprimido** de la carpeta del backend: las
   carpetas `app`, `scripts`, `docs`, `tests` y los archivos sueltos
   (`Dockerfile`, `requirements.txt`, `render.yaml`, `fly.toml`, `README.md`,
   `.gitignore`).
6. **Commit changes**.

No subas el archivo `.env` si llegaste a crearlo. El `.gitignore` ya lo excluye,
pero si lo arrastras a mano el navegador no lo filtra.

---

## Camino A — Render, sólo con el navegador

**Lo que conviene saber antes:** el plan gratuito de Render duerme el servicio
tras quince minutos sin uso y tarda unos segundos en despertar, y **su base de
datos gratuita se borra a los 30 días de creada, sin aviso y sin recuperación**.
Para una defensa en las próximas semanas sirve; para que dure, hay que cambiar
el plan de la base a `basic-256mb`, que cuesta unos siete dólares al mes.

1. Entra a **render.com** y crea la cuenta con **Sign in with GitHub**.
2. **New → Blueprint**.
3. Elige el repositorio `PG2-Abigail`. Render encuentra solo el archivo
   `render.yaml` y muestra lo que va a crear: el servicio web y la base.
4. **Apply**. Tarda entre tres y seis minutos en el primer despliegue.
5. Cuando termine, tu URL aparece arriba y es del tipo
   `https://abigail-partidas.onrender.com`.

### Recuperar la contraseña de administración

Render generó sola la clave maestra y la contraseña. Para verla:

**Dashboard → abigail-partidas → Environment → `ADMIN_PASSWORD`** → el ojito.

Guárdala donde guardes tus contraseñas. El usuario es `admin`.

### Comprobar que quedó bien

Abre en el navegador `https://TU-URL/salud`. Debe responder:

```json
{"estado":"operativo","version":"2.0.0","entorno":"produccion"}
```

Y la prueba de verdad, desde cualquier equipo con Python:

```bash
python scripts/partida_de_prueba.py https://TU-URL
```

Si imprime el código de partida al final, la cadena completa funciona.

---

## Camino B — Fly.io, con SQLite y sin caducidad

Necesita instalar una herramienta de línea de comandos, pero a cambio los datos
no desaparecen y no hay arranques en frío.

1. Instala `flyctl`:
   - Windows (PowerShell): `iwr https://fly.io/install.ps1 -useb | iex`
   - macOS o Linux: `curl -L https://fly.io/install.sh | sh`
2. `fly auth signup` (pide tarjeta, pero el consumo real queda en unos tres
   dólares al mes con la máquina más pequeña).
3. Desde la carpeta del proyecto:

```bash
fly launch --no-deploy --copy-config
fly volumes create datos_abigail --size 1 --region mia

fly secrets set CLAVE_MAESTRA=$(python -c "import secrets;print(secrets.token_hex(48))")
fly secrets set ADMIN_PASSWORD='elige-una-contraseña-larga'

fly deploy
```

4. `fly open /salud` para comprobarlo.

La región `mia` (Miami) es la más cercana a Guatemala de las disponibles.

---

## Poner Cloudflare delante (gratis, 10 minutos)

Esto es lo que de verdad responde a «por si me lo intentan tumbar». El límite de
tasa de la aplicación protege contra una máquina insistente; Cloudflare protege
contra muchas a la vez, y además esconde la dirección real del servidor.

Necesitas un dominio propio. Si no tienes, sáltate este apartado: la aplicación
ya se defiende de lo razonable.

1. Crea la cuenta en **cloudflare.com** y añade tu dominio.
2. Cambia los servidores de nombres donde compraste el dominio por los que
   Cloudflare te indique.
3. **DNS → Add record**: tipo `CNAME`, nombre `api`, destino tu URL de Render o
   Fly, con la nube **naranja** activada (proxy encendido).
4. **SSL/TLS → Overview → Full (strict)**.
5. **Security → WAF → Rate limiting rules → Create rule**:
   - Si la petición empieza por `/v1/`
   - más de **60 peticiones por minuto** desde la misma IP
   - entonces **Block** durante 10 minutos.
6. **Security → Bots → Bot Fight Mode: On**.

Después, en el servicio, cambia `CABECERA_IP_CONFIABLE` a `CF-Connecting-IP`
para que el límite de tasa de la aplicación siga viendo la IP real.

---

## Lo que hay que hacer después de desplegar

**Apunta la URL en el juego.** En Unreal: *Project Settings → Plugins → Project
Abigail*, campo «URL de la API». Debe empezar por `https://`.

**Descarga el CSV de vez en cuando.** No esperes al final:

```
https://TU-URL/v1/admin/exportar.csv
```

Pide el token primero:

```bash
curl -X POST https://TU-URL/v1/admin/acceso \
  -H 'Content-Type: application/json' \
  -d '{"usuario":"admin","password":"TU-CONTRASEÑA"}'

curl https://TU-URL/v1/admin/exportar.csv \
  -H "Authorization: Bearer EL-TOKEN-QUE-DEVOLVIÓ" -o partidas.csv
```

Ese archivo es tu respaldo. Si la plataforma borra la base, lo que ya
descargaste sigue siendo tuyo.

**Comprueba la bitácora antes de la defensa.** `GET /v1/admin/integridad` debe
responder `"cadena_intacta": true`. Es la prueba de que nadie manipuló los
registros, y es un buen dato para mencionar si preguntan por la fiabilidad de
los datos.

---

## Si algo sale mal

| Síntoma | Causa probable | Qué hacer |
|---|---|---|
| El despliegue falla al construir | Falta algún archivo en el repositorio | Revisa que `Dockerfile` y `requirements.txt` estén en la raíz, no dentro de una carpeta |
| `clave_maestra ausente en producción` | La variable no se creó | Render: Environment → Add → `CLAVE_MAESTRA` con 96 caracteres hexadecimales |
| La primera petición tarda 30 segundos | El plan gratuito estaba dormido | Normal. Entra a `/salud` un minuto antes de la demostración |
| `401` en todas las peticiones firmadas | El reloj del equipo está desfasado | Sincroniza la hora; la ventana es de 120 segundos |
| `429` constante | El límite de tasa es bajo para tu prueba | Sube `LIMITE_PETICIONES_POR_IP_MINUTO` en las variables de entorno |
| La base está vacía tras un redespliegue | SQLite sin volumen montado | En Fly, comprueba que el volumen `datos_abigail` esté montado en `/datos` |
