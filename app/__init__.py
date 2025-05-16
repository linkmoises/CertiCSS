from flask import Flask
from pymongo import MongoClient
from config import config
# from app.auth import token_required
# from flask_login import login_required, current_user

# Inicializar Flask
app = Flask(__name__)
app.config.from_object(config)                  # importado de config.py

# Configuración de MongoDB
client = MongoClient(config.MONGO_URI)          # importado de config.py
db = client['certi_css']                         # importado de config.py

# Inicializar las colecciones
collection_eventos = db['eventos']              # importado de config.py
collection_usuarios = db['usuarios']            # importado de config.py
collection_participantes = db['participantes']  # importado de config.py
collection_eva = db['eva']
collection_tokens = db['tokens']

# Exportar variables necesarias
BASE_URL = config.BASE_URL                      # importado de config.py