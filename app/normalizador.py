###
###
###  Este archivo contiene las rutas y funciones relacionadas con la normalización de los nombres
###  en la base de datos.
### 
###
###
from flask import Flask, Blueprint, render_template, render_template_string, send_file
from flask_login import login_required
from datetime import datetime
import os


normalizador_blueprint = Blueprint('normalizador', __name__)