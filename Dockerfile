FROM python:3.12-slim

WORKDIR /app

# Instalar locales, libmagic y dependencias del sistema para WeasyPrint
RUN apt-get update && apt-get install -y --no-install-recommends locales libmagic1 \
    libpango-1.0-0 libpangocairo-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf-2.0-0 \
    libffi-dev libcairo2 libcairo2-dev libglib2.0-0 shared-mime-info && \
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

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "60", "wsgi:app"]