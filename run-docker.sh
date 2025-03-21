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
BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD)
COMMIT_HASH=$(git rev-parse --short HEAD)
VERSION="${BRANCH_NAME}-${COMMIT_HASH}"
echo "$VERSION" > version.txt
echo "Versión generada: $VERSION"

# Construir y levantar los contenedores
echo "Construyendo y levantando contenedores..."
#docker-compose up --build -d
docker-compose up --build --force-recreate -d

echo "¡Despliegue completado!"