#!/bin/bash

# Script para instalar dependencias de CertiCSS de manera gradual
# Evita problemas con matplotlib y numpy

set -e

echo "=== Instalando dependencias de CertiCSS ==="

# Activar entorno virtual
source venv/bin/activate

# Actualizar pip
echo "Actualizando pip..."
pip install --upgrade pip

# Dependencias básicas de Flask
echo "Instalando dependencias básicas de Flask..."
pip install flask flask-login flask-pymongo

# Dependencias de seguridad y utilidades
echo "Instalando dependencias de seguridad..."
pip install werkzeug markupsafe

# Dependencias de base de datos
echo "Instalando dependencias de MongoDB..."
pip install pymongo dnspython

# Dependencias de procesamiento de imágenes
echo "Instalando Pillow..."
pip install pillow

# Dependencias de documentos PDF
echo "Instalando dependencias de PDF..."
pip install reportlab pdfrw

# Dependencias de códigos QR
echo "Instalando qrcode..."
pip install qrcode

# Dependencias de texto y markdown
echo "Instalando dependencias de texto..."
pip install markdown

# Dependencias de requests
echo "Instalando requests..."
pip install requests urllib3 certifi chardet charset-normalizer idna

# Dependencias básicas de sistema
echo "Instalando dependencias básicas..."
pip install click blinker itsdangerous jinja2 docopt pipreqs yarg

# Servidor web para producción
echo "Instalando gunicorn..."
pip install gunicorn

# OpenAI (opcional)
echo "Instalando OpenAI..."
pip install openai || echo "OpenAI falló, continuando..."

# Intentar instalar numpy y matplotlib por separado
echo "Intentando instalar numpy..."
pip install "numpy==1.23" || echo "Numpy falló, continuando sin gráficos..."

echo "Intentando instalar matplotlib..."
pip install matplotlib || echo "Matplotlib falló, continuando sin gráficos..."

echo "Intentando instalar pandas..."
pip install "pandas==2.2.0" || echo "Pandas falló, continuando sin análisis de datos..."

echo "Intentando instalar seaborn..."
pip install seaborn || echo "Seaborn falló, continuando sin gráficos avanzados..."

echo
echo "✓ Instalación de dependencias completada"
echo "Nota: Algunas dependencias opcionales pueden haber fallado, pero la aplicación debería funcionar."