#!/usr/bin/env python3
"""
Script de prueba para el sistema de concurso de póster científico
"""

import requests
import json
from datetime import datetime

# Configuración
BASE_URL = "http://localhost:5000"
CODIGO_EVENTO = "TEST01"  # Cambiar por un código de evento real

def test_poster_registration():
    """Prueba el registro de un póster"""
    print("🧪 Probando registro de póster...")
    
    url = f"{BASE_URL}/registrar_poster/{CODIGO_EVENTO}"
    data = {
        'nombres': 'Juan Carlos',
        'apellidos': 'Pérez García',
        'cedula': '8-123-456',
        'email': 'juan.perez@test.com',
        'telefono': '6123-4567',
        'institucion': 'Universidad de Panamá',
        'titulo_poster': 'Análisis de Algoritmos de Machine Learning en Datos Médicos',
        'passphrase': 'mi_passphrase_segura_123'
    }
    
    try:
        response = requests.post(url, data=data)
        if response.status_code == 200:
            print("✅ Registro de póster exitoso")
        else:
            print(f"❌ Error en registro de póster: {response.status_code}")
    except Exception as e:
        print(f"❌ Error de conexión: {e}")

def test_jury_registration():
    """Prueba el registro de un jurado"""
    print("🧪 Probando registro de jurado...")
    
    url = f"{BASE_URL}/registrar_jurado/{CODIGO_EVENTO}"
    data = {
        'nombres': 'María Elena',
        'apellidos': 'González López',
        'cedula': '8-987-654',
        'email': 'maria.gonzalez@test.com',
        'institucion': 'Instituto de Investigación',
        'especialidad': 'Inteligencia Artificial y Machine Learning',
        'passphrase': 'jurado_passphrase_456'
    }
    
    try:
        response = requests.post(url, data=data)
        if response.status_code == 200:
            print("✅ Registro de jurado exitoso")
        else:
            print(f"❌ Error en registro de jurado: {response.status_code}")
    except Exception as e:
        print(f"❌ Error de conexión: {e}")

def test_poster_login():
    """Prueba el login de presentador"""
    print("🧪 Probando login de presentador...")
    
    url = f"{BASE_URL}/poster_login/{CODIGO_EVENTO}"
    data = {
        'cedula': '8-123-456',
        'passphrase': 'mi_passphrase_segura_123'
    }
    
    try:
        response = requests.post(url, data=data)
        if response.status_code == 200:
            print("✅ Login de presentador exitoso")
        else:
            print(f"❌ Error en login de presentador: {response.status_code}")
    except Exception as e:
        print(f"❌ Error de conexión: {e}")

def test_jury_login():
    """Prueba el login de jurado"""
    print("🧪 Probando login de jurado...")
    
    url = f"{BASE_URL}/jurado_login/{CODIGO_EVENTO}"
    data = {
        'cedula': '8-987-654',
        'passphrase': 'jurado_passphrase_456'
    }
    
    try:
        response = requests.post(url, data=data)
        if response.status_code == 200:
            print("✅ Login de jurado exitoso")
        else:
            print(f"❌ Error en login de jurado: {response.status_code}")
    except Exception as e:
        print(f"❌ Error de conexión: {e}")

def test_info_page():
    """Prueba la página de información del concurso"""
    print("🧪 Probando página de información...")
    
    url = f"{BASE_URL}/concurso_poster/{CODIGO_EVENTO}"
    
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print("✅ Página de información accesible")
        else:
            print(f"❌ Error en página de información: {response.status_code}")
    except Exception as e:
        print(f"❌ Error de conexión: {e}")

def main():
    """Ejecuta todas las pruebas"""
    print("🚀 Iniciando pruebas del sistema de concurso de póster científico")
    print(f"📍 URL base: {BASE_URL}")
    print(f"📅 Código de evento: {CODIGO_EVENTO}")
    print("\n⚠️  IMPORTANTE: Asegúrate de que el evento tenga habilitado el 'Concurso de Póster'")
    print("   en el formulario de creación/edición de eventos.")
    print("-" * 60)
    
    # Pruebas básicas
    test_info_page()
    test_poster_registration()
    test_jury_registration()
    test_poster_login()
    test_jury_login()
    
    print("-" * 60)
    print("✨ Pruebas completadas")
    print("\n📋 URLs importantes:")
    print(f"• Información del concurso: {BASE_URL}/concurso_poster/{CODIGO_EVENTO}")
    print(f"• Registro de póster: {BASE_URL}/registrar_poster/{CODIGO_EVENTO}")
    print(f"• Registro de jurado: {BASE_URL}/registrar_jurado/{CODIGO_EVENTO}")
    print(f"• Login presentador: {BASE_URL}/poster_login/{CODIGO_EVENTO}")
    print(f"• Login jurado: {BASE_URL}/jurado_login/{CODIGO_EVENTO}")

if __name__ == "__main__":
    main()