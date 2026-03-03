###
###
###  Este archivo contiene las rutas y funciones relacionadas con el manejo de logs en la 
###  aplicación.
### 
###  - `show_latest_log`: Muestra el contenido del último archivo de log en el tablero.
###  - `download_latest_log`: Permite descargar el último archivo de log generado.
###  - `get_latest_log_file`: Función auxiliar que encuentra el archivo de log más reciente en el 
###     directorio de logs.
###
###
from flask import Flask, Blueprint, render_template, render_template_string, send_file, request
from flask_login import login_required
from datetime import datetime
import os
import logging
from logging.handlers import RotatingFileHandler


logs_blueprint = Blueprint('logs', __name__)

# Logger centralizado de la aplicación
logger = None

def get_logger():
    """Obtiene o crea el logger centralizado para toda la aplicación"""
    global logger
    
    if logger is not None:
        return logger
    
    # Crear la carpeta /logs si no existe
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # Nombre del archivo de log basado en la fecha actual
    log_filename = datetime.now().strftime('logs/app-%Y-%m-%d.log')

    # Configuración del logging
    logger = logging.getLogger('certicss_logger')
    logger.setLevel(logging.DEBUG)

    # Formato del log
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Manejador para archivo (production)
    file_handler = RotatingFileHandler(
        log_filename,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=250,
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Manejador para consola (development)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

# Inicializar logger al importar el módulo
get_logger()

def get_client_ip():
    """Obtiene la dirección IP del cliente."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    else:
        return request.environ.get('REMOTE_ADDR', 'unknown')

def log_event(message):
    """Función centralizada para logging de eventos de usuario"""
    logger = get_logger()
    client_ip = get_client_ip()
    log_message = f"{message} {client_ip}."
    logger.info(log_message)


###
### Permite mostrar el último log en el tablero.
###
@logs_blueprint.route('/logs')
@login_required
def show_latest_log():
    latest_log_file = get_latest_log_file()

    if not latest_log_file:
        return "No hay archivos de registro de actividades."

    with open(latest_log_file, 'r') as file:
        log_content = file.read()

    return render_template('logs.html', log_file=latest_log_file, log_content=log_content)


###
### Permite descargar el último log generado.
###
@logs_blueprint.route('/descargar_log')
@login_required
def download_latest_log():
    latest_log_file = get_latest_log_file()

    if not latest_log_file:
        return "No hay archivos de registro de actividades."

    now = datetime.now()
    formatted_datetime = now.strftime("app-%Y-%m-%d-%H-%M-%S.log")

    return send_file(latest_log_file, as_attachment=True, download_name=formatted_datetime)


###
### Función para encontrar el log más reciente en el directorio de logs.
###
def get_latest_log_file():
    log_dir = 'logs'
    log_files = [f for f in os.listdir(log_dir) if f.startswith('app-') and f.endswith('.log')]

    if not log_files:
        return None

    # Ordenar los archivos por fecha (el más reciente primero)
    log_files.sort(reverse=True)

    # Devolver la ruta completa del archivo más reciente
    return os.path.join(log_dir, log_files[0])