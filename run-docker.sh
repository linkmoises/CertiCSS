#!/bin/bash

usage() {
  echo "Uso: $0 [commit=<hash>]"
  echo ""
  echo "  Sin parámetros    Despliega la versión actual del repositorio."
  echo "  commit=<hash>     Revierte el repositorio al commit indicado y lo despliega."
  exit 1
}

# Validar que el comando git esté disponible
if ! command -v git &> /dev/null; then
  echo "Error: git no está instalado."
  exit 1
fi

# Parsear argumentos
for arg in "$@"; do
  case $arg in
    commit=*)
      COMMIT="${arg#*=}"
      if [ -z "$COMMIT" ]; then
        echo "Error: Debes especificar un hash de commit."
        usage
      fi
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Error: Argumento desconocido: $arg"
      usage
      ;;
  esac
done

if [ -n "$COMMIT" ]; then
  echo "Revirtiendo al commit: $COMMIT"
  git fetch --all
  git checkout "$COMMIT"
else
  # Actualizar cambios en el repositorio
  git pull
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
docker compose up --build --force-recreate -d

# Limpiar imágenes no utilizadas
echo "Limpiando imágenes no utilizadas..."
docker image prune -f

echo "¡Despliegue completado!"
