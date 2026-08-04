#!/bin/bash
set -euo pipefail

# Despliegue sin internet para servidores restringidos (podman rootless).
# Replica docker-compose.yml sin necesitar podman-compose ni docker.
# Uso: ./run-podman-offline.sh [ruta/al/certicss-stack.tar.gz]

cd "$(dirname "$0")"

NET="docenciamedica_net"
TARBALL="${1:-certicss-stack.tar.gz}"

# 1) Cargar imágenes si el tarball está presente
if [ -f "$TARBALL" ]; then
  echo "Cargando imágenes desde $TARBALL ..."
  gzip -dc "$TARBALL" | podman load
fi

# 2) Asegurar directorios de datos (bind mounts)
mkdir -p ../static_certificados ../static_uploads ../static_usuarios \
         ../static_audio ../static_nube ../logs ../db_data

# 3) Red
podman network exists "$NET" 2>/dev/null || podman network create "$NET"

# 4) Base de datos
podman rm -f db 2>/dev/null || true
podman run -d --name db --restart always \
  --network "$NET" \
  -e TZ=America/Panama \
  -v "$PWD/../db_data:/data/db:z" \
  mongo:6.0
echo "Esperando que MongoDB arranque..."
for i in $(seq 1 30); do
  if podman exec db mongosh --quiet --eval "db.adminCommand('ping')" >/dev/null 2>&1; then
    echo "MongoDB listo."
    break
  fi
  sleep 2
done

# 5) Web (usa el código dentro de la imagen, no bind-mount de código)
podman rm -f web 2>/dev/null || true
podman run -d --name web --restart always \
  --network "$NET" \
  -p 5000:5000 \
  -e FLASK_HOST=0.0.0.0 \
  -e FLASK_PORT=5000 \
  -e MONGO_URI=mongodb://db:27017/ \
  -e TZ=America/Panama \
  --env-file .env \
  -v "$PWD/../static_certificados:/app/static/certificados:z" \
  -v "$PWD/../static_uploads:/app/static/uploads:z" \
  -v "$PWD/../static_usuarios:/app/static/usuarios:z" \
  -v "$PWD/../static_audio:/app/static/audio:z" \
  -v "$PWD/../static_nube:/app/static/nube:z" \
  -v "$PWD/../logs:/app/logs:z" \
  certicss-web:latest

# 6) Tunnel (opcional: requiere TUNNEL_TOKEN en .env)
TUNNEL_TOKEN=$(grep -E '^TUNNEL_TOKEN=' .env 2>/dev/null | head -1 | cut -d= -f2-)
if [ -n "${TUNNEL_TOKEN:-}" ]; then
  podman rm -f tunnel 2>/dev/null || true
  podman run -d --name tunnel --restart always \
    --network "$NET" \
    --env-file .env \
    cloudflare/cloudflared:latest tunnel --no-autoupdate run --token "$TUNNEL_TOKEN"
else
  echo "AVISO: TUNNEL_TOKEN no está en .env, omitiendo el túnel."
fi

# 7) Versión
BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "offline")
COMMIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "imagen")
echo "${BRANCH_NAME}-${COMMIT_HASH}" > version.txt

echo "¡Despliegue completado!"
podman ps
