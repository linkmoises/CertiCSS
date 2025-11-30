#!/bin/bash

# Configuración
BACKUP_DIR="./backups"

# Colores para output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

if [ -z "$1" ]; then
    echo -e "${YELLOW}Uso: ./restore.sh <TIMESTAMP>${NC}"
    echo "Ejemplo: ./restore.sh 20251130_120000"
    echo ""
    echo "Backups disponibles:"
    ls -1 "$BACKUP_DIR" | grep "mongo_dump_" | sed 's/mongo_dump_//' | sed 's/.archive//' | sort -r | head -n 5
    exit 1
fi

TIMESTAMP="$1"
MONGO_ARCHIVE="$BACKUP_DIR/mongo_dump_$TIMESTAMP.archive"
STATIC_TAR="$BACKUP_DIR/static_files_$TIMESTAMP.tar.gz"

echo -e "${YELLOW}ATENCIÓN: Este script sobrescribirá la base de datos actual y los archivos estáticos.${NC}"
echo "Restaurando backup del: $TIMESTAMP"
read -p "¿Estás seguro de continuar? (s/n): " confirm
if [[ $confirm != "s" && $confirm != "S" ]]; then
    echo "Operación cancelada."
    exit 0
fi

# 1. Restaurar Base de Datos
if [ -f "$MONGO_ARCHIVE" ]; then
    echo "Restaurando base de datos desde $MONGO_ARCHIVE..."
    # --drop elimina las colecciones existentes antes de restaurar
    cat "$MONGO_ARCHIVE" | docker-compose exec -T db mongorestore --archive --gzip --drop
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Base de datos restaurada correctamente.${NC}"
    else
        echo -e "${RED}Error al restaurar la base de datos.${NC}"
        exit 1
    fi
else
    echo -e "${RED}No se encontró el archivo de backup de base de datos: $MONGO_ARCHIVE${NC}"
    exit 1
fi

# 2. Restaurar Archivos Estáticos
if [ -f "$STATIC_TAR" ]; then
    echo "Restaurando archivos estáticos desde $STATIC_TAR..."
    
    # Extraer en el directorio padre (..)
    tar -xzf "$STATIC_TAR" -C ..
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Archivos estáticos restaurados correctamente.${NC}"
    else
        echo -e "${RED}Error al restaurar archivos estáticos.${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}No se encontró el archivo de backup de estáticos: $STATIC_TAR (Se omitirá)${NC}"
fi

echo -e "${GREEN}¡Proceso de restauración finalizado!${NC}"
echo "Es recomendable reiniciar los contenedores: docker-compose restart"
