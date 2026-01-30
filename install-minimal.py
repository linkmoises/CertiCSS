#!/usr/bin/env python3
"""
Script de instalación mínima para CertiCSS
Solo instala las dependencias básicas necesarias para la configuración inicial
"""

import sys
import os

def verificar_dependencias():
    """Verificar que las dependencias mínimas estén instaladas"""
    dependencias = ['pymongo', 'flask', 'werkzeug']
    faltantes = []
    
    for dep in dependencias:
        try:
            __import__(dep)
            print(f"✓ {dep} instalado")
        except ImportError:
            faltantes.append(dep)
            print(f"✗ {dep} faltante")
    
    if faltantes:
        print(f"\nInstala las dependencias faltantes:")
        print(f"pip install {' '.join(faltantes)}")
        return False
    
    return True

def verificar_mongodb():
    """Verificar que MongoDB esté ejecutándose"""
    try:
        from pymongo import MongoClient
        from pymongo.errors import ServerSelectionTimeoutError, ConnectionFailure
        
        client = MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=5000)
        client.server_info()  # Forzar conexión
        print("✓ MongoDB está ejecutándose correctamente")
        return client
    except (ServerSelectionTimeoutError, ConnectionFailure) as e:
        print("✗ Error: No se puede conectar a MongoDB")
        print("Asegúrate de que MongoDB esté instalado y ejecutándose:")
        print("  sudo systemctl start mongod")
        print("  sudo systemctl status mongod")
        return None
    except ImportError:
        print("✗ Error: pymongo no está instalado")
        print("Instala pymongo: pip install pymongo")
        return None

def crear_usuario_admin(client):
    """Crear usuario administrador en la base de datos"""
    from werkzeug.security import generate_password_hash
    from datetime import datetime
    
    db = client['certi_css']
    collection_usuarios = db['usuarios']
    
    print("\n=== Configuración del Usuario Administrador ===")
    
    # Verificar si ya existe un administrador
    admin_existente = collection_usuarios.find_one({"rol": "administrador"})
    if admin_existente:
        print(f"Ya existe un usuario administrador: {admin_existente.get('email', 'N/A')}")
        respuesta = input("¿Deseas crear otro administrador? (s/N): ").lower().strip()
        if respuesta not in ['s', 'si', 'sí', 'y', 'yes']:
            print("Instalación cancelada.")
            return False
    
    while True:
        email_admin = input("Introduce el nombre de usuario para el rol de administrador: ").strip()
        if not email_admin:
            print("El nombre de usuario no puede estar vacío.")
            continue
        
        # Verificar si el usuario ya existe
        if collection_usuarios.find_one({"email": email_admin}):
            print(f"El usuario '{email_admin}' ya existe.")
            continue
        break
    
    while True:
        password_admin = input("Introduce la contraseña (mínimo 6 caracteres): ").strip()
        if len(password_admin) < 6:
            print("La contraseña debe tener al menos 6 caracteres.")
            continue
        break

    try:
        # Hashear la contraseña
        hashed_password = generate_password_hash(password_admin)

        # Crear el usuario administrador en la base de datos
        resultado = collection_usuarios.insert_one({
            "email": email_admin,
            "nombres": "Administrador",
            "password": hashed_password,
            "rol": "administrador",
            "activo": True,
            "permisos": [],
            "timestamp": datetime.now()
        })

        if resultado.inserted_id:
            print(f"✓ Usuario administrador '{email_admin}' creado con éxito.")
            print(f"✓ ID del usuario: {resultado.inserted_id}")
            return True
        else:
            print("✗ Error al crear el usuario administrador.")
            return False
            
    except Exception as e:
        print(f"✗ Error al crear el usuario: {e}")
        return False

def main():
    print("=== Instalador Mínimo de CertiCSS ===")
    print("Este script configurará la base de datos y creará un usuario administrador.")
    print()
    
    # Verificar dependencias
    if not verificar_dependencias():
        sys.exit(1)
    
    # Verificar MongoDB
    client = verificar_mongodb()
    if not client:
        sys.exit(1)
    
    try:
        if crear_usuario_admin(client):
            print("\n=== Instalación Completada ===")
            print("✓ MongoDB conectado correctamente")
            print("✓ Base de datos 'certi_css' configurada")
            print("✓ Usuario administrador creado")
            print("\nPróximos pasos:")
            print("1. Instala las dependencias completas: pip install -r requirements.txt")
            print("2. Ejecuta: ./run-local.sh")
            print("3. Abre tu navegador en: http://localhost:5000")
        else:
            print("\n✗ La instalación no se completó correctamente.")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nInstalación cancelada por el usuario.")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error inesperado durante la instalación: {e}")
        sys.exit(1)
    finally:
        if client:
            client.close()

if __name__ == "__main__":
    main()