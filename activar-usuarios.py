from pymongo import MongoClient
from datetime import datetime

# Conectar a MongoDB
mongo_uri = os.getenv("MONGO_URI", "mongodb://db:27017/")
client = MongoClient(mongo_uri)
db = client['certi_css']
collection_usuarios = db['usuarios']

# Actualizar todos los usuarios para añadir el campo "activo"
collection_usuarios.update_many(
    {},  # Filtro vacío para aplicar a todos los documentos
    {"$set": {"activo": True}}  # Valor predeterminado para usuarios normales
)

print("Campo 'activo' añadido a todos los usuarios.")