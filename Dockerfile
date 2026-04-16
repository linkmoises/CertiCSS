FROM python:3.12-slim

WORKDIR /app

# Instalar locales y generar el español de Panamá
RUN apt-get update && apt-get install -y --no-install-recommends locales libmagic1 && \
    echo "es_PA.UTF-8 UTF-8" >> /etc/locale.gen && \
    locale-gen && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configurar las variables de entorno para que Python use el locale correcto
ENV LANG=es_PA.UTF-8
ENV LC_ALL=es_PA.UTF-8

# Copiar dependencias primero para aprovechar el cache de capas
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el resto del código al final
COPY . .

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "60", "app:app"]