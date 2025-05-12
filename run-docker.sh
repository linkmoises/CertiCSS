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

# Actualizar cambios en el repositorio
git pull

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

# Limpiar imágenes no utilizadas
echo "Limpiando imágenes no utilizadas..."
docker image prune -f

echo "¡Despliegue completado!"