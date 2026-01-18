###
###
###  Este archivo contiene las rutas y funciones relacionadas con la visualización de 
###  eventos por unidades ejecutoras
### 
###
###
from flask import Flask, Blueprint, render_template, render_template_string, send_file, request, redirect, url_for
from app import db, collection_eventos, collection_participantes
from flask_login import login_required, current_user
from datetime import datetime

unidades_bp = Blueprint('unidades', __name__)


###
### Catálogo de unidades ejecutoras
###
@unidades_bp.route('/catalogo/unidades')
def catalogo_unidades():
    return render_template('catalogo_unidades.html')


###
### Docencia semanal por unidad específica
###
@unidades_bp.route('/catalogo/unidades/<codigo_unidad>')
def docencia_unidad(codigo_unidad):
    # Aquí puedes agregar lógica para obtener eventos específicos de la unidad
    # Por ahora retornamos un template básico
    return render_template('catalogo_unidad.html', codigo_unidad=codigo_unidad)