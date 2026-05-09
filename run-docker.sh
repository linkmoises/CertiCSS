#!/bin/bash

usage() {
  echo "Uso: $0 [commit=<hash>]"
  echo ""
  echo "  Sin parámetros    Despliega la versión actual del repositorio."
  echo "  commit=<hash>     Revierte al commit indicado y lo despliega."
  exit 1
}

if ! command -v git &> /dev/null; then
  echo "Error: git no está instalado."
  exit 1
fi

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
  if ! git rev-parse --verify "$COMMIT" &> /dev/null; then
    echo "Error: El commit '$COMMIT' no existe."
    exit 1
  fi

  if [ -n "$(git status --porcelain)" ]; then
    echo "Guardando cambios locales en stash..."
    git stash push -m "run-docker.sh rollback $(date)"
  fi

  echo "Revirtiendo al commit: $COMMIT"
  git checkout "$COMMIT"

  BUILD_OPTS="--no-cache"
else
  git pull
  BUILD_OPTS=""
fi

echo "Generando version.txt..."
BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD)
COMMIT_HASH=$(git rev-parse --short HEAD)
VERSION="${BRANCH_NAME}-${COMMIT_HASH}"
echo "$VERSION" > version.txt
echo "Versión generada: $VERSION"

echo "Construyendo y levantando contenedores..."
docker compose build $BUILD_OPTS && docker compose up --force-recreate -d

echo "Limpiando imágenes no utilizadas..."
docker image prune -f

if [ -n "$(git stash list)" ]; then
  echo "Restaurando cambios locales..."
  git stash pop
fi

echo "¡Despliegue completado!"
