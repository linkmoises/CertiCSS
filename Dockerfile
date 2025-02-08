FROM python:3.9-slim

WORKDIR /app

# Instalar locales y generar el español de Panamá
RUN apt-get update && apt-get install -y locales && \
    echo "es_PA.UTF-8 UTF-8" >> /etc/locale.gen && \
    locale-gen && \
    apt-get clean

# Configurar las variables de entorno para que Python use el locale correcto
ENV LANG=es_PA.UTF-8  
ENV LC_ALL=es_PA.UTF-8  

COPY app.py .

COPY requirements.txt .

RUN pip install -r requirements.txt

EXPOSE 5000

CMD ["python", "app.py"]