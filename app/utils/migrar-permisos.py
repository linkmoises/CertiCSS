#!/usr/bin/env python3
"""
Script de migración para agregar el campo 'permisos' a todos los usuarios existentes.
Este script debe ejecutarse una sola vez después de implementar el sistema de permisos.
"""

from pymongo import MongoClient
import os

# Configurar conexión a MongoDB
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
client = MongoClient(MONGO_URI)
db = client['certi_css']
collection_usuarios = db['usuarios']

def migrar_permisos():
    """Agrega el campo permisos vacío a todos los usuarios que no lo tengan"""
    
    # Contar usuarios sin el campo permisos
    usuarios_sin_permisos = collection_usuarios.count_documents({
        "permisos": {"$exists": False}
    })
    
    if usuarios_sin_permisos == 0:
        print("✓ Todos los usuarios ya tienen el campo 'permisos'")
        return
    
    print(f"Encontrados {usuarios_sin_permisos} usuarios sin el campo 'permisos'")
    print("Agregando campo 'permisos' vacío...")
    
    # Actualizar todos los usuarios que no tengan el campo permisos
    result = collection_usuarios.update_many(
        {"permisos": {"$exists": False}},
        {"$set": {"permisos": []}}
    )
    
    print(f"✓ Migración completada: {result.modified_count} usuarios actualizados")
    
    # Verificar
    total_usuarios = collection_usuarios.count_documents({})
    usuarios_con_permisos = collection_usuarios.count_documents({
        "permisos": {"$exists": True}
    })
    
    print(f"\nEstadísticas:")
    print(f"  Total de usuarios: {total_usuarios}")
    print(f"  Usuarios con campo permisos: {usuarios_con_permisos}")

if __name__ == "__main__":
    print("=== Migración de Sistema de Permisos ===\n")
    try:
        migrar_permisos()
        print("\n✓ Migración exitosa")
    except Exception as e:
        print(f"\n✗ Error durante la migración: {e}")
        exit(1)
