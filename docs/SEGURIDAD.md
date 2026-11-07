# Modelo de amenazas y controles de seguridad

Project Abigail — Registro de Partidas · Versión 2.0 · Noviembre de 2026

Este documento describe contra qué se protege el servicio, con qué mecanismos
y cuáles son los límites reconocidos de esa protección. Está redactado para
acompañar la documentación técnica del proyecto de graduación.

---

## I. Alcance y premisa

El sistema expone una API que recibe los datos de las partidas jugadas
desde un cliente de videojuego distribuido públicamente.

La premisa de la que parte todo el diseño es que **el cliente no es
confiable**. El ejecutable se descarga, corre en hardware ajeno y puede
inspeccionarse, modificarse o sustituirse por completo. De esa premisa se
derivan dos consecuencias que condicionan la arquitectura:

1. Ningún secreto embebido en el cliente es realmente secreto. Por eso no
   existe ninguna clave de larga vida compartida con el juego.
2. Ninguna afirmación del cliente puede aceptarse sin contrastarla. Por eso
   el cierre de la partida se contrasta con la telemetría ya registrada.

---

## II. Activos a proteger

| Activo | Por qué importa |
|---|---|
| Integridad de los indicadores de partida | Alimentan el análisis del estudio; datos falsos invalidan conclusiones |
| Integridad de la telemetría | Es el registro de lo que ocurrió durante la partida |
| Bitácora de auditoría | Es el registro de lo que ocurrió; si se altera, no hay forma de reconstruirlo |
| Credenciales de administración | Dan acceso a la exportación de datos |
| Clave maestra | De ella se derivan todas las claves de sesión |
| Disponibilidad del servicio | Su caída interrumpe la recolección de datos del playtesting |

No hay datos personales entre los activos, y eso es deliberado: el estudio se
comprometió a recolección anónima, de modo que el sistema no almacena nombres,
correos ni direcciones IP en claro.

---

## III. Amenazas identificadas y controles

### A. Suplantación del cliente

**Amenaza.** Cualquiera puede construir peticiones HTTP a mano y hacerse pasar
por el juego.

**Control.** Firma HMAC-SHA256 por petición con una clave efímera derivada por
sesión mediante HKDF (RFC 5869) a partir de la clave maestra. La clave se
entrega una sola vez al abrir la sesión y el servidor no la almacena: la
vuelve a derivar del identificador de sesión cuando la necesita. Sólo guarda
una huella SHA-256 para detectar inconsistencias.

**Límite reconocido.** Quien extraiga la clave de la memoria del proceso puede
firmar peticiones válidas durante la vida de esa sesión. El control no hace
imposible el fraude: eleva su costo desde «editar un JSON» hasta «hacer
ingeniería inversa del cliente», y lo circunscribe a una sola sesión.

### B. Alteración del contenido en tránsito

**Amenaza.** Un proxy intermedio modifica el cuerpo de una petición legítima.

**Control.** La cadena canónica que se firma incluye el hash SHA-256 del
cuerpo completo, además del método y la ruta. Alterar un solo byte invalida la
firma. Incluir método y ruta impide además reutilizar una firma válida de un
endpoint en otro.

### C. Repetición de peticiones

**Amenaza.** Capturar una petición válida y reenviarla muchas veces.

**Control.** Dos mecanismos combinados. Cada petición lleva un nonce de 128
bits que el servidor registra y rechaza si vuelve a aparecer, y una marca de
tiempo que debe caer dentro de una ventana de 120 segundos. La ventana acota
el tamaño de la tabla de nonces; el nonce cubre la repetición dentro de la
ventana.

### D. Partidas inventadas o indicadores falseados

**Amenaza.** Alguien envía partidas que nunca se jugaron, o cierra una partida
real con indicadores manipulados, para desplazar los resultados del estudio.

**Control.** Tres barreras encadenadas. La primera es la firma: sin la clave
efímera que el servidor entregó al abrir la partida no se puede construir una
petición válida, y esa clave no está en el ejecutable. La segunda es la lista
blanca de tipos de evento y el rango declarado de cada indicador: un porcentaje
de 140 o un desenlace inventado se rechazan en la validación, antes de tocar la
base. La tercera es el cierre único: una partida no se puede cerrar dos veces
con cifras distintas, porque el segundo intento devuelve el cierre existente sin
alterarlo.

**Residual.** Quien extraiga la clave de la memoria del proceso durante una
partida real puede enviar indicadores coherentes pero falsos. Contrarrestarlo por
completo exigiría atestación del cliente, que excede el alcance del proyecto. Lo
que sí queda es rastro: el número de eventos, su secuencia temporal y la
bitácora permiten detectar una partida que no se comporta como las demás.

### E. Manipulación de la bitácora

**Amenaza.** Alguien con acceso a la base de datos borra o altera registros
para ocultar actividad.

**Control.** Bitácora encadenada por hash: cada entrada incorpora el hash de
la anterior, calculado sobre su contenido completo. Modificar o eliminar
cualquier registro rompe la cadena a partir de ese punto. El endpoint
`/v1/admin/integridad` recorre la cadena y señala la primera entrada
inconsistente.

**Límite reconocido.** La cadena detecta la manipulación pero no la impide, y
quien tenga acceso de escritura podría recalcular toda la cadena. Para
impedirlo haría falta anclar los hashes en un almacén externo de sólo
anexado.

### F. Fuerza bruta contra la administración

**Amenaza.** Adivinar la contraseña de administración por repetición.

**Control.** Argon2id con parámetros por encima del mínimo recomendado por
OWASP (3 iteraciones, 64 MiB de memoria, paralelismo 4). Bloqueo temporal de
quince minutos tras cinco intentos fallidos. La verificación se ejecuta contra
un hash aunque la cuenta no exista, para que el tiempo de respuesta no revele
qué usuarios están registrados. Rehash automático si los parámetros cambian.

### G. Denegación de servicio y abuso de recursos

**Amenaza.** Saturar el servicio con peticiones o cuerpos muy grandes.

**Control.** Cuatro límites independientes: sesiones por origen y hora,
peticiones por sesión y minuto, eventos por partida, y tamaño máximo del
cuerpo (32 KiB, verificado antes de leerlo). Los esquemas de entrada acotan
además el número de claves y la profundidad de los objetos JSON libres, de
modo que la columna JSON no se convierta en vector de abuso.

### H. Inyección

**Amenaza.** Inyección SQL u otra manipulación de consultas.

**Control.** Todo el acceso a datos pasa por SQLAlchemy con parámetros
vinculados; no se construye SQL por concatenación en ningún punto. La entrada
se valida con Pydantic mediante expresiones regulares y rangos explícitos
antes de llegar a la capa de datos.

### I. Fuga de información

**Amenaza.** Los mensajes de error revelan detalles internos aprovechables.

**Control.** Un manejador global convierte cualquier excepción no prevista en
un 500 genérico, registrando la traza sólo del lado del servidor. En
producción se desactivan `/docs` y `/openapi.json`. Se eliminan las cabeceras
que identifican la tecnología del servidor.

---

## IV. Controles transversales

| Control | Implementación |
|---|---|
| Cabeceras de seguridad | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Content-Security-Policy`, `Permissions-Policy`, `Cache-Control` y HSTS en producción |
| CORS | Desactivado salvo configuración explícita; el cliente de UE5 no lo requiere |
| Gestión de secretos | Exclusivamente por variables de entorno; `.env` excluido del control de versiones; la aplicación se niega a arrancar en producción sin clave maestra válida |
| Contenedor | Usuario sin privilegios, sistema de archivos de sólo lectura, todas las capacidades de Linux descartadas, `no-new-privileges` |
| Red | La base de datos no publica puertos; sólo es accesible desde la red interna de Docker |
| Comparaciones | Las de firma usan `hmac.compare_digest`, en tiempo constante |

---

## V. Privacidad

El servicio no recopila datos personales. Las sesiones se identifican con
UUID aleatorios sin vínculo con la persona. Las direcciones IP se emplean
únicamente para limitar la tasa y se seudonimizan antes con HMAC-SHA256 bajo
la clave maestra, de modo que la dirección original nunca se escribe en la
base de datos ni en la bitácora.

Esta decisión es coherente con el compromiso del estudio: los cuestionarios no
solicitan nombre, correo ni ningún dato identificable, y el backend mantiene
la misma norma.

---

## VI. Lo que este sistema no cubre

Enumerarlo es parte de la honestidad del diseño.

1. **No hay atestación del cliente.** El servidor no puede comprobar que quien
   habla es el ejecutable original y no una reimplementación.
2. **No hay cifrado de la clave en reposo en el cliente.** Mientras la sesión
   viva, la clave está en memoria del proceso y es extraíble.
3. **La bitácora detecta manipulación pero no la impide.** Haría falta un
   almacén externo de sólo anexado.
4. **Sin TLS, nada de lo anterior se sostiene.** La clave de sesión viaja en
   la respuesta de apertura; en claro, cualquiera en la ruta la captura. El
   despliegue en producción con HTTPS no es opcional.
5. **No se simula la partida en el servidor.** La validación comprueba
   coherencia, no autenticidad absoluta de la telemetría.

---

## VII. Verificación

Los controles descritos están cubiertos por la suite de pruebas:

| Prueba | Control verificado |
|---|---|
| `test_firma_invalida_es_rechazada` | A |
| `test_cuerpo_alterado_invalida_la_firma` | B |
| `test_firma_de_una_ruta_no_sirve_en_otra` | B |
| `test_repeticion_de_nonce_es_rechazada` | C |
| `test_marca_de_tiempo_antigua_es_rechazada` | C |
| `test_indicadores_fuera_de_rango_se_rechazan` | D |
| `test_cierre_es_idempotente` | D |
| `test_rechaza_tipo_de_evento_desconocido` | D |
| `test_no_se_admiten_eventos_tras_el_cierre` | D |
| `test_bitacora_intacta_tras_operar` | E |
| `test_diez_firmas_invalidas_revocan_la_sesion` | A, G |
| `test_entrada_malformada_es_rechazada` | H |
| `test_json_anidado_en_los_datos_es_rechazado` | G, H |
| `test_cabeceras_de_seguridad_presentes` | Transversales |

`pytest -q` ejecuta las 25 pruebas. `python scripts/demo_cliente.py` demuestra
los tres ataques principales contra un servidor en ejecución.
