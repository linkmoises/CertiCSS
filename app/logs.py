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
from flask import Flask, Blueprint, render_template, render_template_string, send_file
from flask_login import login_required
from datetime import datetime
import os


logs_blueprint = Blueprint('logs', __name__)


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