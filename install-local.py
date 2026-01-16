from flask import Flask
from werkzeug.security import generate_password_hash
from pymongo import MongoClient
from flask_pymongo import PyMongo
from datetime import datetime

# Configuración de Flask y MongoDB
app = Flask(__name__)
client = MongoClient('mongodb://localhost:27017/')
db = client['certi_css']
collection_usuarios = db['usuarios']

# Verificar si la base de datos y la colección existen
if 'certi_css' not in client.list_database_names():
    print("La base de datos 'certi_css' no existe. Creándola...")
    db = client['certi_css']

if 'usuarios' not in db.list_collection_names():
    print("La colección 'usuarios' no existe. Creándola...")
    collection_usuarios = db['usuarios']

def crear_usuario_admin():
    email_admin = input("Introduce el nombre de usuario para el rol de administrador: ")  # Solicitar usuario
    password_admin = input("Introduce la contraseña: ")  # Solicitar contraseña

    # Hashear la contraseña
    hashed_password = generate_password_hash(password_admin)

    # Verificar si el usuario ya existe
    if collection_usuarios.find_one({"email": email_admin}):
        print("El usuario administrador ya existe.")
        return

    # Crear el usuario administrador en la base de datos
    collection_usuarios.insert_one({
        "email": email_admin,
        "nombres": "Administrador",
        "password": hashed_password,
        "rol": "administrador",
        "activo": True,
        "permisos": [],  # Los administradores no necesitan permisos adicionales
        "timestamp": datetime.now()
    })

    print("Usuario administrador creado con éxito.")

if __name__ == "__main__":
    crear_usuario_admin()
