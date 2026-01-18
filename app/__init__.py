from flask import Flask
from pymongo import MongoClient
from config import config
from datetime import datetime
# from app.auth import token_required
# from flask_login import login_required, current_user

# Inicializar Flask
app = Flask(__name__)
app.config.from_object(config)                  # importado de config.py

# Filtro personalizado para formatear fechas
def format_date(value, format='%d/%m/%y'):
    if not value:
        return ''
    if isinstance(value, str):
        try:
            # Intentar convertir de string a datetime
            value = datetime.strptime(value, '%Y-%m-%d')
        except (ValueError, TypeError):
            return value
    try:
        return value.strftime(format)
    except (AttributeError, ValueError):
        return value

# Registrar el filtro en la aplicación
app.jinja_env.filters['date'] = format_date                  # importado de config.py

# Configuración de MongoDB
client = MongoClient(config.MONGO_URI)          # importado de config.py
db = client['certi_css']                         # importado de config.py

# Inicializar las colecciones
collection_eventos = db['eventos']              # importado de config.py
collection_usuarios = db['usuarios']            # importado de config.py
collection_participantes = db['participantes']  # importado de config.py
collection_eva = db['eva']
collection_tokens = db['tokens']
collection_qbanks = db['qbanks']
collection_qbanks_data = db['qbanks_data']
collection_exam_results = db['exam_results']
collection_nube = db['nube_archivos']
collection_unidades = db['unidades']

# Exportar variables necesarias
BASE_URL = config.BASE_URL                      # importado de config.py