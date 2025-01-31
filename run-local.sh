#!/bin/bash

###    ./run_local.sh          # Ejecuta el script normalmente
###    ./run_local.sh -r       # Reinstala las dependencias
###    ./run_local.sh -f       # Forza la creación de un nuevo entorno virtual
###    ./run_local.sh -rf      # Reinstala dependencias y fuerza un nuevo entorno virtual

# Opciones
REINSTALL_DEPENDENCIES=false
FORCE_NEW_VENV=false

while getopts "rf" opt; do
  case $opt in
    r) REINSTALL_DEPENDENCIES=true ;;
    f) FORCE_NEW_VENV=true ;;
    *) echo "Uso: $0 [-r] [-f]" >&2
       exit 1 ;;
  esac
done

# Validar que el comando git esté disponible
if ! command -v git &> /dev/null; then
  echo "Error: git no está instalado."
  exit 1
fi

# Validar que python esté instalado
if ! command -v python &> /dev/null; then
  echo "Error: python no está instalado."
  exit 1
fi

# Generar version.txt
echo "Generando version.txt..."
git rev-parse --short HEAD > version.txt
echo "Versión generada: $(cat version.txt)"

# Manejar el entorno virtual
if [ "$FORCE_NEW_VENV" = true ]; then
  echo "Forzando la creación de un nuevo entorno virtual..."
  rm -rf venv
fi

if [ -d "venv" ]; then
  echo "Activando entorno virtual..."
  source venv/bin/activate
else
  echo "Creando entorno virtual..."
  python -m venv venv
  source venv/bin/activate
fi

# Instalar dependencias
if [ "$REINSTALL_DEPENDENCIES" = true ] || [ ! -f "venv/updated" ]; then
  echo "Instalando dependencias..."
  pip install -r requirements.txt
  touch venv/updated
else
  echo "Dependencias ya instaladas."
fi

# Ejecutar la aplicación
echo "Ejecutando la aplicación..."
python app.py