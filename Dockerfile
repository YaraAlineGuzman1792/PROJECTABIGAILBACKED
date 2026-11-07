FROM python:3.12-slim

# Usuario sin privilegios: el proceso nunca corre como root.
RUN groupadd -r abigail && useradd -r -g abigail -d /app abigail

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PORT=8000

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts

# Carpeta del archivo SQLite. En producción se monta encima un volumen para
# que los datos sobrevivan a los redespliegues.
RUN mkdir -p /app/datos && chown -R abigail:abigail /app

USER abigail
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen(f\"http://localhost:{os.environ.get('PORT','8000')}/salud\").status==200 else 1)"

# --proxy-headers para que la IP real llegue desde el balanceador de la
# plataforma; sin él, el límite de tasa vería una sola dirección para todos.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'"]
