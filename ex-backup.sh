#!/bin/bash

# Configuración
BACKUP_DIR="./backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
DB_CONTAINER_NAME="certicss_db_1" # Ajustar si el nombre del contenedor es diferente, o usar docker-compose
# Nota: Usaremos docker-compose para ser más genéricos respecto al nombre del contenedor

# Colores para output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Iniciando respaldo...${NC}"
echo "Timestamp: $TIMESTAMP"

# Crear directorio de backups si no existe
if [ ! -d "$BACKUP_DIR" ]; then
    mkdir -p "$BACKUP_DIR"
    echo "Directorio de backups creado en $BACKUP_DIR"
fi

# 1. Respaldo de Base de Datos (MongoDB)
echo "Respaldando base de datos..."
# Usamos 'docker-compose exec' para ejecutar mongodump dentro del contenedor
# -T evita errores de TTY cuando se ejecuta desde cron
if docker-compose exec -T db mongodump --archive --gzip > "$BACKUP_DIR/mongo_dump_$TIMESTAMP.archive"; then
    echo -e "${GREEN}Base de datos respaldada correctamente: mongo_dump_$TIMESTAMP.archive${NC}"
else
    echo -e "${RED}Error al respaldar la base de datos.${NC}"
    exit 1
fi

# 2. Respaldo de Archivos Estáticos (Volúmenes)
echo "Respaldando archivos estáticos..."
# Comprimimos las carpetas que están un nivel arriba (../static_*)
# Asumimos que el script se ejecuta desde la raíz del proyecto (donde está docker-compose.yml)
TAR_NAME="static_files_$TIMESTAMP.tar.gz"

# Lista de carpetas a respaldar (relativas al directorio padre del proyecto)
FOLDERS="static_certificados static_uploads static_usuarios static_audio"

# Verificamos que las carpetas existan antes de intentar comprimirlas
FOLDERS_TO_BACKUP=""
for folder in $FOLDERS; do
    if [ -d "../$folder" ]; then
        FOLDERS_TO_BACKUP="$FOLDERS_TO_BACKUP $folder"
    else
        echo "Advertencia: La carpeta ../$folder no existe, se omitirá."
    fi
done

if [ -n "$FOLDERS_TO_BACKUP" ]; then
    # Ejecutamos tar desde el directorio padre para mantener la estructura relativa correcta
    tar -czf "$BACKUP_DIR/$TAR_NAME" -C .. $FOLDERS_TO_BACKUP
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Archivos estáticos respaldados correctamente: $TAR_NAME${NC}"
    else
        echo -e "${RED}Error al comprimir archivos estáticos.${NC}"
        exit 1
    fi
else
    echo "No se encontraron carpetas estáticas para respaldar."
fi

# 3. Limpieza de backups antiguos (Opcional: mantener últimos 7 días)
# find "$BACKUP_DIR" -type f -mtime +7 -name "*.archive" -delete
# find "$BACKUP_DIR" -type f -mtime +7 -name "*.tar.gz" -delete
# echo "Backups antiguos eliminados."

echo -e "${GREEN}¡Proceso de respaldo finalizado con éxito!${NC}"
