FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependencias del sistema si se necesitan (ej. gnupg si luego usas sa-update con firmas)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /app/app/

EXPOSE 8080

CMD ["uvicorn", "app.main:api", "--host", "0.0.0.0", "--port", "8080"]
