from pymongo import MongoClient
from datetime import datetime

# Conectar a MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['certi_css']
collection_usuarios = db['usuarios']

# Actualizar todos los usuarios para añadir el campo "activo"
collection_usuarios.update_many(
    {},  # Filtro vacío para aplicar a todos los documentos
    {"$set": {"activo": True}}  # Valor predeterminado para usuarios normales
)

print("Campo 'activo' añadido a todos los usuarios.")