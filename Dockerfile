FROM python:3.9-slim

# Establecer el directorio de trabajo
WORKDIR /app

# Copiar el archivo app.py
COPY app.py .

# Copiar el archivo requirements.txt (si lo tienes)
COPY requirements.txt .

# Instalar dependencias
RUN pip install -r requirements.txt

# Exponer el puerto
EXPOSE 5000

# Comando para ejecutar al iniciar el contenedor
CMD ["python", "app.py"]