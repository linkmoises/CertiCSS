#!/bin/bash

# Validar que el comando git esté disponible
if ! command -v git &> /dev/null; then
  echo "Error: git no está instalado."
  exit 1
fi

# Validar que docker-compose esté instalado
if ! command -v docker-compose &> /dev/null; then
  echo "Error: docker-compose no está instalado."
  exit 1
fi

# Generar version.txt
echo "Generando version.txt..."
git rev-parse --short HEAD > version.txt
echo "Versión generada: $(cat version.txt)"

# Construir y levantar los contenedores
echo "Construyendo y levantando contenedores..."
#docker-compose up --build -d
docker-compose up --build --force-recreate

echo "¡Despliegue completado!"