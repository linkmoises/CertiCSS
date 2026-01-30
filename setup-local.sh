#!/bin/bash

###
### Script de instalación completa para CertiCSS (Desarrollo Local)
### Este script configura todo lo necesario para ejecutar CertiCSS localmente
###

set -e  # Salir si cualquier comando falla

echo "=== Instalador Completo de CertiCSS (Local) ==="
echo "Este script configurará todo lo necesario para ejecutar CertiCSS localmente."
echo

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Función para mostrar mensajes
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "ℹ $1"
}

# Verificar que estamos en el directorio correcto
if [ ! -f "app.py" ] || [ ! -f "requirements.txt" ]; then
    print_error "Este script debe ejecutarse desde el directorio raíz de CertiCSS"
    exit 1
fi

# Verificar dependencias del sistema
print_info "Verificando dependencias del sistema..."

# Verificar Python
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 no está instalado"
    print_info "Instala Python 3: sudo apt update && sudo apt install python3 python3-pip python3-venv"
    exit 1
fi
print_success "Python 3 encontrado: $(python3 --version)"

# Verificar Git
if ! command -v git &> /dev/null; then
    print_error "Git no está instalado"
    print_info "Instala Git: sudo apt update && sudo apt install git"
    exit 1
fi
print_success "Git encontrado: $(git --version)"

# Verificar MongoDB
print_info "Verificando MongoDB..."
if ! command -v mongod &> /dev/null; then
    print_error "MongoDB no está instalado"
    print_info "Instala MongoDB siguiendo: https://docs.mongodb.com/manual/tutorial/install-mongodb-on-ubuntu/"
    exit 1
fi

# Verificar si MongoDB está ejecutándose
if ! pgrep -x "mongod" > /dev/null; then
    print_warning "MongoDB no está ejecutándose. Intentando iniciarlo..."
    if sudo systemctl start mongod 2>/dev/null; then
        print_success "MongoDB iniciado correctamente"
    else
        print_error "No se pudo iniciar MongoDB automáticamente"
        print_info "Inicia MongoDB manualmente: sudo systemctl start mongod"
        exit 1
    fi
else
    print_success "MongoDB está ejecutándose"
fi

# Habilitar MongoDB para que inicie automáticamente
if sudo systemctl enable mongod 2>/dev/null; then
    print_success "MongoDB configurado para iniciar automáticamente"
fi

# Generar version.txt
print_info "Generando información de versión..."
if [ -d ".git" ]; then
    BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
    COMMIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    VERSION="${BRANCH_NAME}-${COMMIT_HASH}"
    echo "$VERSION" > version.txt
    print_success "Versión generada: $VERSION"
else
    echo "local-dev" > version.txt
    print_warning "No es un repositorio Git, usando versión: local-dev"
fi

# Configurar entorno virtual
print_info "Configurando entorno virtual de Python..."
if [ -d "venv" ]; then
    print_warning "El entorno virtual ya existe. ¿Deseas recrearlo? (s/N)"
    read -r response
    if [[ "$response" =~ ^([sS][iI]?|[yY][eE][sS]?)$ ]]; then
        rm -rf venv
        print_info "Entorno virtual eliminado"
    fi
fi

if [ ! -d "venv" ]; then
    print_info "Creando entorno virtual..."
    python3 -m venv venv
    print_success "Entorno virtual creado"
fi

# Activar entorno virtual e instalar dependencias
print_info "Instalando dependencias de Python..."
source venv/bin/activate

# Actualizar pip
pip install --upgrade pip > /dev/null 2>&1

# Instalar dependencias usando el script gradual
print_info "Instalando dependencias (esto puede tomar varios minutos)..."
if ./install-deps.sh > /dev/null 2>&1; then
    print_success "Dependencias instaladas correctamente"
else
    print_warning "Algunas dependencias fallaron, pero las básicas están instaladas"
    print_info "La aplicación debería funcionar con funcionalidad limitada"
fi

# Crear archivo .env si no existe
if [ ! -f ".env" ]; then
    print_info "Creando archivo de configuración .env..."
    cp .env.example .env
    print_success "Archivo .env creado desde .env.example"
    print_warning "Revisa y modifica .env según tus necesidades"
fi

# Ejecutar script de instalación de base de datos
print_info "Configurando base de datos y usuario administrador..."
echo
python install-minimal.py

if [ $? -eq 0 ]; then
    echo
    print_success "¡Instalación completada exitosamente!"
    echo
    print_info "Para ejecutar la aplicación:"
    print_info "  ./run-local.sh"
    echo
    print_info "O manualmente:"
    print_info "  source venv/bin/activate"
    print_info "  python app.py"
    echo
    print_info "La aplicación estará disponible en: http://localhost:5000"
    echo
else
    print_error "Error durante la configuración de la base de datos"
    exit 1
fi