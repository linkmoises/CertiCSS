from flask import Flask, render_template, abort
from flask_login import current_user
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
collection_posters = db['posters']
collection_evaluaciones_poster = db['evaluaciones_poster']

# Exportar variables necesarias
BASE_URL = config.BASE_URL                      # importado de config.py


def listar_participantes(codigo_evento):
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)

    puede_editar = (
        current_user.rol == 'administrador' or
        current_user.rol == 'denadoi' or
        str(current_user.id) == str(evento.get("autor")) or
        collection_participantes.find_one({
            "codigo_evento": codigo_evento,
            "cedula": str(current_user.cedula),
            "rol": "coorganizador"
        })
    )

    role_order = {"organizador": 0, "coorganizador": 1, "ponente": 2, "participante": 3}

    participantes = list(collection_participantes.find(
        {"codigo_evento": codigo_evento}
    ))

    participantes.sort(key=lambda p: (
        role_order.get(p.get("rol", "participante"), 3),
        p.get("fecha_evento") or p.get("timestamp") or ""
    ))

    total_participantes = len([p for p in participantes if p.get('rol') == 'participante'])
    total_ponentes = len([p for p in participantes if p.get('rol') == 'ponente'])

    return render_template('participantes.html',
                           evento=evento,
                           participantes=participantes,
                           nombre_evento=evento['nombre'],
                           total_participantes=total_participantes,
                           total_ponentes=total_ponentes,
                           codigo_evento=codigo_evento,
                           puede_editar=puede_editar)