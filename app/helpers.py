###
###
###  Este archivo contiene funciones utilitarias y helpers para la aplicación CertiCSS
###  que son utilizadas por diferentes funciones independientes
###
###
import os
import random
import string
import hashlib
from datetime import datetime, timedelta


# Almacenamiento global para OTPs
otp_storage = {}


def generate_otp():
    """Genera un código OTP de 4 dígitos (mayúsculas y números)."""
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for _ in range(4))


def generate_nanoid(cedula, codigo_evento, titulo_ponencia=None):
    """Genera un hash nanoid truncado a 8 caracteres utilizando cédula, código de evento y opcionalmente título de ponencia."""
    # Si no se proporciona un título de ponencia, usar una cadena vacía
    if titulo_ponencia is None:
        titulo_ponencia = ""
    base_string = f"{cedula}{codigo_evento}{titulo_ponencia}"
    hash_object = hashlib.sha256(base_string.encode())
    return hash_object.hexdigest()[:8]


def generar_codigo_evento(longitud=6):
    """Genera un código aleatorio para eventos."""
    caracteres = string.ascii_uppercase + string.digits
    codigo = ''.join(random.choice(caracteres) for _ in range(longitud))
    return codigo


def obtener_codigo_unico(collection_eventos):
    """Genera un código único para evento verificando que no exista en la base de datos."""
    while True:
        codigo = generar_codigo_evento()
        if collection_eventos.find_one({"codigo": codigo}) is None:
            return codigo


def allowed_file(filename, allowed_extensions=None):
    """
    Verifica si la extensión del archivo está permitida.
    
    Args:
        filename (str): Nombre del archivo a verificar
        allowed_extensions (set): Conjunto de extensiones permitidas. 
                                Si es None, usa extensiones por defecto.
    
    Returns:
        bool: True si la extensión está permitida, False en caso contrario
    """
    if allowed_extensions is None:
        # Extensiones por defecto (las más comunes en la aplicación)
        allowed_extensions = {'png', 'jpg', 'jpeg', 'pdf', 'ppt', 'pptx', 'doc', 'docx'}
    
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


def allowed_file_images(filename):
    """Verifica si el archivo es una imagen permitida."""
    return allowed_file(filename, {'png', 'jpg', 'jpeg'})


def allowed_file_documents(filename):
    """Verifica si el archivo es un documento permitido."""
    return allowed_file(filename, {'pdf', 'ppt', 'pptx', 'doc', 'docx'})


def allowed_file_all(filename):
    """Verifica si el archivo tiene una extensión permitida (todas las extensiones)."""
    return allowed_file(filename, {'png', 'jpg', 'jpeg', 'pdf', 'ppt', 'pptx', 'doc', 'docx'})