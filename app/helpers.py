###
###
###  Este archivo contiene funciones utilitarias y helpers para la aplicación CertiCSS
###  que son utilizadas por diferentes funciones independientes
###
###
import os
import re
import random
import string
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Tuple, List

# Detección de MIME types (opcional - fallback a extensión si no está disponible)
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

# Mime types permitidos para uploads
ALLOWED_IMAGE_MIMETYPES = {'image/jpeg', 'image/png', 'image/gif', 'image/webp'}
ALLOWED_DOCUMENT_MIMETYPES = {
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'text/plain',
    'text/markdown',
}


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


###
### Funciones de validación de entrada
###

def validate_cedula(cedula: str) -> Tuple[bool, Optional[str]]:
    """
    Valida el formato de cédula panameña.
    
    Formatos válidos:
    - N-NNN-NNNN (ej: 8-888-8888)
    - NNNNNNNN (8 dígitos)
    
    Args:
        cedula: Número de cédula a validar
        
    Returns:
        Tupla (es_válido, mensaje_error)
    """
    if not cedula:
        return False, "La cédula es requerida"
    
    cedula = cedula.strip()
    
    # Formato con guiones: N-NNN-NNNN
    pattern_guiones = r'^\d-\d{3}-\d{4}$'
    # Formato de 8 dígitos
    pattern_digits = r'^\d{8}$'
    
    if re.match(pattern_guiones, cedula) or re.match(pattern_digits, cedula):
        return True, None
    
    return False, "Formato de cédula inválido. Use formato N-NNN-NNNN o 8 dígitos"


def validate_email(email: str) -> Tuple[bool, Optional[str]]:
    """
    Valida el formato de correo electrónico.
    
    Args:
        email: Correo electrónico a validar
        
    Returns:
        Tupla (es_válido, mensaje_error)
    """
    if not email:
        return False, "El correo electrónico es requerido"
    
    email = email.strip().lower()
    
    # RFC 5322 simplificado
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if re.match(pattern, email) and len(email) <= 254:
        return True, None
    
    return False, "Formato de correo electrónico inválido"


def validate_name(nombre: str, field_name: str = "Nombre") -> Tuple[bool, Optional[str]]:
    """
    Valida nombres y apellidos.
    
    Args:
        nombre: Nombre a validar
        field_name: Nombre del campo para el mensaje de error
        
    Returns:
        Tupla (es_válido, mensaje_error)
    """
    if not nombre:
        return False, f"{field_name} es requerido"
    
    nombre = nombre.strip()
    
    if len(nombre) < 2:
        return False, f"{field_name} debe tener al menos 2 caracteres"
    
    if len(nombre) > 100:
        return False, f"{field_name} no puede exceder 100 caracteres"
    
    # No permitir números ni caracteres especiales (excepto espacios, tildes, ñ)
    pattern = r'^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s\-\.]+$'
    if not re.match(pattern, nombre):
        return False, f"{field_name} no puede contener números o caracteres especiales"
    
    return True, None


def validate_event_code(codigo: str) -> Tuple[bool, Optional[str]]:
    """
    Valida el código de evento.
    
    Args:
        codigo: Código de evento a validar
        
    Returns:
        Tupla (es_válido, mensaje_error)
    """
    if not codigo:
        return False, "El código del evento es requerido"
    
    codigo = codigo.strip().upper()
    
    if len(codigo) < 4 or len(codigo) > 20:
        return False, "El código debe tener entre 4 y 20 caracteres"
    
    # Solo permite letras y números
    pattern = r'^[A-Z0-9]+$'
    if not re.match(pattern, codigo):
        return False, "El código solo puede contener letras y números"
    
    return True, None


def validate_phone(phone: str) -> Tuple[bool, Optional[str]]:
    """
    Valida números de teléfono panameños.
    
    Formatos válidos:
    - +507 XXXXXXX
    - 6XXXXXXX
    - XXXX-XXXX
    
    Args:
        phone: Número de teléfono a validar
        
    Returns:
        Tupla (es_válido, mensaje_error)
    """
    if not phone:
        return True, None  # Teléfono es opcional
    
    phone = phone.strip()
    
    # Remover espacios y guiones para validar
    phone_clean = phone.replace(' ', '').replace('-', '')
    
    # +507 seguido de 7 dígitos
    pattern_intl = r'^\+507\d{7}$'
    # 6 o 7 seguido de 6 dígitos
    pattern_local = r'^[67]\d{6}$'
    # 8 dígitos
    pattern_digits = r'^\d{8}$'
    
    if re.match(pattern_intl, phone_clean) or re.match(pattern_local, phone_clean) or re.match(pattern_digits, phone_clean):
        return True, None
    
    return False, "Formato de teléfono inválido"


def validate_orcid(orcid: str) -> Tuple[bool, Optional[str]]:
    """
    Valida el formato ORCID.
    
    Formato: XXXX-XXXX-XXXX-XXXX
    
    Args:
        orcid: Identificador ORCID a validar
        
    Returns:
        Tupla (es_válido, mensaje_error)
    """
    if not orcid:
        return True, None  # ORCID es opcional
    
    orcid = orcid.strip()
    
    pattern = r'^\d{4}-\d{4}-\d{4}-\d{4}$'
    if re.match(pattern, orcid):
        return True, None
    
    return False, "Formato ORCID inválido (XXXX-XXXX-XXXX-XXXX)"


def validate_file_content(file_storage, allowed_mimetypes: set) -> Tuple[bool, Optional[str]]:
    """
    Valida el contenido real de un archivo subiendo.
    
    Args:
        file_storage: Werkzeug FileStorage object
        allowed_mimetypes: Conjunto de MIME types permitidos
        
    Returns:
        Tupla (es_válido, mensaje_error)
    """
    if not file_storage or not file_storage.filename:
        return False, "No se ha proporcionado ningún archivo"
    
    # Si magic no está disponible, fall back a solo extensión
    if not MAGIC_AVAILABLE:
        return True, None
    
    try:
        # Leer los primeros bytes para detectar el tipo MIME real
        file_storage.seek(0)
        file_header = file_storage.read(2048)
        file_storage.seek(0)
        
        # Usar python-magic para detectar el tipo MIME real
        detected_mimetype = magic.from_buffer(file_header, mime=True)
        
        if detected_mimetype in allowed_mimetypes:
            return True, None
        
        return False, f"Tipo de archivo no permitido: {detected_mimetype}"
    
    except Exception:
        # Si falla la detección, fallback a extensión
        return True, None


def validate_text_field(value: str, field_name: str, min_length: int = 0, max_length: int = 5000, required: bool = True) -> Tuple[bool, Optional[str]]:
    """
    Valida un campo de texto genérico.
    
    Args:
        value: Valor a validar
        field_name: Nombre del campo para mensajes de error
        min_length: Longitud mínima
        max_length: Longitud máxima
        required: Si el campo es obligatorio
        
    Returns:
        Tupla (es_válido, mensaje_error)
    """
    if not value or not value.strip():
        if required:
            return False, f"{field_name} es requerido"
        return True, None
    
    value = value.strip()
    
    if len(value) < min_length:
        return False, f"{field_name} debe tener al menos {min_length} caracteres"
    
    if len(value) > max_length:
        return False, f"{field_name} no puede exceder {max_length} caracteres"
    
    return True, None


def sanitize_html(text: str) -> str:
    """
    Sanitiza texto para prevenir XSS.
    Escapa caracteres HTML problemáticos.
    
    Args:
        text: Texto a sanitizar
        
    Returns:
        Texto sanitizado
    """
    if not text:
        return ""
    
    #替换 HTML entities
    replacements = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;',
    }
    
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    
    return text


def validate_certificate_template(evento):
    """Validate that a certificate template exists and is accessible for an event."""
    import os
    certificado_path = evento.get('certificado')
    if not certificado_path or not certificado_path.strip():
        return False
    try:
        return os.path.exists(certificado_path) and os.path.isfile(certificado_path)
    except (OSError, TypeError):
        return False


def validate_attendance_template(evento):
    """Validate that an attendance certificate template exists and is accessible for an event."""
    import os
    constancia_path = evento.get('constancia')
    if not constancia_path or not constancia_path.strip():
        return False
    try:
        return os.path.exists(constancia_path) and os.path.isfile(constancia_path)
    except (OSError, TypeError):
        return False
