###
###
###  Este archivo contiene las rutas y funciones relacionadas con la visualización de 
###  eventos según provincias
### 
###
###
from flask import Flask, Blueprint, render_template, render_template_string, send_file, request, redirect, url_for
from app import db, collection_participantes
from flask_login import login_required

regiones_bp = Blueprint('regiones', __name__)

###
### Permite mostrar el último log en el tablero.
###
@regiones_bp.route('/tablero/eventos/provincias')
@login_required
def eventos_region():
    return render_template('eventos-regiones.html')