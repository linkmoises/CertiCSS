###
###
###  Este archivo contiene las rutas y funciones relacionadas con el almacenamiento
###  en la nube personal de cada usuario
### 
###
###
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_from_directory, jsonify, abort
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId
from datetime import datetime
import os
import secrets
from app import db, collection_usuarios, collection_nube

nube_bp = Blueprint('nube', __name__)

# Importar función de logging centralizada
from app.logs import log_event
from app.helpers import allowed_file

# Configuración específica para archivos de la nube
NUBE_ALLOWED_EXTENSIONS = {'pdf', 'ppt', 'pptx', 'doc', 'docx', 'txt', 'md', 'jpg', 'png', 'xls', 'xlsx'}

# Configuración específica para la nube
NUBE_FOLDER = 'static/nube'
MAX_USER_STORAGE = 256 * 1024 * 1024  # 256 MB en bytes
# La colección collection_nube se importa desde app/__init__.py

def allowed_file_nube(filename):
    """Verifica si la extensión del archivo está permitida para la nube."""
    return allowed_file(filename, NUBE_ALLOWED_EXTENSIONS)

def get_user_folder_path(user_id):
    """Obtiene la ruta de la carpeta del usuario."""
    return os.path.join(NUBE_FOLDER, str(user_id))

def get_user_storage_usage(user_id):
    """Calcula el uso actual de almacenamiento del usuario."""
    user_folder = get_user_folder_path(user_id)
    if not os.path.exists(user_folder):
        return 0
    
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(user_folder):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            if os.path.exists(filepath):
                total_size += os.path.getsize(filepath)
    return total_size

def format_file_size(size_bytes):
    """Convierte bytes a formato legible."""
    if size_bytes == 0:
        return "0 B"
    size_names = ["B", "KB", "MB", "GB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    return f"{size_bytes:.1f} {size_names[i]}"

@nube_bp.route('/tablero/nube')
@login_required
def nube_dashboard():
    """Dashboard principal de la nube del usuario."""
    user_id = current_user.id
    
    # Crear carpeta del usuario si no existe
    user_folder = get_user_folder_path(user_id)
    os.makedirs(user_folder, exist_ok=True)
    
    # Obtener archivos del usuario
    archivos = list(collection_nube.find({"usuario_id": user_id}).sort("fecha_subida", -1))
    
    # Calcular uso de almacenamiento
    storage_used = get_user_storage_usage(user_id)
    storage_percentage = (storage_used / MAX_USER_STORAGE) * 100
    
    # Obtener archivos compartidos conmigo
    archivos_compartidos = list(collection_nube.find({
        "compartido_publico": True,
        "usuario_id": {"$ne": user_id}
    }).sort("fecha_subida", -1).limit(10))
    
    # Agregar información del propietario a archivos compartidos
    for archivo in archivos_compartidos:
        propietario = collection_usuarios.find_one({"_id": ObjectId(archivo["usuario_id"])})
        if propietario:
            archivo["propietario_nombre"] = f"{propietario.get('nombres', '')} {propietario.get('apellidos', '')}"
    
    return render_template('nube_dashboard.html',
        archivos=archivos,
        archivos_compartidos=archivos_compartidos,
        storage_used=format_file_size(storage_used),
        storage_total=format_file_size(MAX_USER_STORAGE),
        storage_percentage=min(storage_percentage, 100)
    )

@nube_bp.route('/tablero/nube/subir', methods=['POST'])
@login_required
def subir_archivo():
    """Subir un archivo a la nube del usuario."""
    if 'archivo' not in request.files:
        flash('No se seleccionó ningún archivo.', 'error')
        return redirect(url_for('nube.nube_dashboard'))
    
    file = request.files['archivo']
    if file.filename == '':
        flash('No se seleccionó ningún archivo.', 'error')
        return redirect(url_for('nube.nube_dashboard'))
    
    if not allowed_file_nube(file.filename):
        flash('Tipo de archivo no permitido.', 'error')
        return redirect(url_for('nube.nube_dashboard'))
    
    user_id = current_user.id
    
    # Verificar límite de almacenamiento
    current_usage = get_user_storage_usage(user_id)
    file_size = len(file.read())
    file.seek(0)  # Resetear el puntero del archivo
    
    if current_usage + file_size > MAX_USER_STORAGE:
        flash('No tienes suficiente espacio de almacenamiento disponible.', 'error')
        return redirect(url_for('nube.nube_dashboard'))
    
    # Generar nombre único para el archivo
    filename = secure_filename(file.filename)
    unique_id = secrets.token_hex(8)
    name, ext = os.path.splitext(filename)
    unique_filename = f"{unique_id}_{filename}"
    
    # Guardar archivo
    user_folder = get_user_folder_path(user_id)
    file_path = os.path.join(user_folder, unique_filename)
    file.save(file_path)
    
    # Guardar información en la base de datos
    archivo_doc = {
        "usuario_id": user_id,
        "nombre_original": filename,
        "nombre_archivo": unique_filename,
        "tamano": file_size,
        "tipo": ext.lower(),
        "fecha_subida": datetime.now(),
        "compartido_publico": False,
        "enlace_publico": None
    }
    
    collection_nube.insert_one(archivo_doc)
    
    log_event(f"Usuario [{current_user.email}] subió el archivo {filename} ({format_file_size(file_size)}) a su nube personal.")
    flash('Archivo subido exitosamente.', 'success')
    return redirect(url_for('nube.nube_dashboard'))

@nube_bp.route('/tablero/nube/eliminar/<archivo_id>', methods=['POST'])
@login_required
def eliminar_archivo(archivo_id):
    """Eliminar un archivo de la nube del usuario."""
    archivo = collection_nube.find_one({
        "_id": ObjectId(archivo_id),
        "usuario_id": current_user.id
    })
    
    if not archivo:
        flash('Archivo no encontrado.', 'error')
        return redirect(url_for('nube.nube_dashboard'))
    
    # Eliminar archivo físico
    user_folder = get_user_folder_path(current_user.id)
    file_path = os.path.join(user_folder, archivo["nombre_archivo"])
    
    if os.path.exists(file_path):
        os.remove(file_path)
    
    # Eliminar de la base de datos
    collection_nube.delete_one({"_id": ObjectId(archivo_id)})
    
    log_event(f"Usuario [{current_user.email}] eliminó el archivo {archivo['nombre_original']} de su nube personal.")
    flash('Archivo eliminado exitosamente.', 'success')
    return redirect(url_for('nube.nube_dashboard'))

@nube_bp.route('/tablero/nube/compartir/<archivo_id>', methods=['POST'])
@login_required
def compartir_archivo(archivo_id):
    """Generar enlace público para compartir un archivo."""
    archivo = collection_nube.find_one({
        "_id": ObjectId(archivo_id),
        "usuario_id": current_user.id
    })
    
    if not archivo:
        flash('Archivo no encontrado.', 'error')
        return redirect(url_for('nube.nube_dashboard'))
    
    # Generar enlace público único
    enlace_publico = secrets.token_urlsafe(32)
    
    # Actualizar archivo en la base de datos
    collection_nube.update_one(
        {"_id": ObjectId(archivo_id)},
        {"$set": {
            "compartido_publico": True,
            "enlace_publico": enlace_publico
        }}
    )
    
    log_event(f"Usuario [{current_user.email}] compartió públicamente el archivo {archivo['nombre_original']}.")
    flash('Enlace público generado exitosamente.', 'success')
    return redirect(url_for('nube.nube_dashboard'))

@nube_bp.route('/tablero/nube/descompartir/<archivo_id>', methods=['POST'])
@login_required
def descompartir_archivo(archivo_id):
    """Desactivar el enlace público de un archivo."""
    archivo = collection_nube.find_one({
        "_id": ObjectId(archivo_id),
        "usuario_id": current_user.id
    })
    
    if not archivo:
        flash('Archivo no encontrado.', 'error')
        return redirect(url_for('nube.nube_dashboard'))
    
    # Desactivar compartir público
    collection_nube.update_one(
        {"_id": ObjectId(archivo_id)},
        {"$set": {
            "compartido_publico": False,
            "enlace_publico": None
        }}
    )
    
    flash('Enlace público desactivado.', 'success')
    return redirect(url_for('nube.nube_dashboard'))

@nube_bp.route('/tablero/nube/descargar/<archivo_id>')
@login_required
def descargar_archivo(archivo_id):
    """Descargar un archivo propio."""
    archivo = collection_nube.find_one({
        "_id": ObjectId(archivo_id),
        "usuario_id": current_user.id
    })
    
    if not archivo:
        abort(404)
    
    user_folder = get_user_folder_path(current_user.id)
    return send_from_directory(
        user_folder,
        archivo["nombre_archivo"],
        as_attachment=True,
        download_name=archivo["nombre_original"]
    )

@nube_bp.route('/nube/publico/<enlace>')
def archivo_publico(enlace):
    """Acceder a un archivo compartido públicamente."""
    archivo = collection_nube.find_one({"enlace_publico": enlace})
    
    if not archivo or not archivo.get("compartido_publico"):
        abort(404)
    
    user_folder = get_user_folder_path(archivo["usuario_id"])
    return send_from_directory(
        user_folder,
        archivo["nombre_archivo"],
        as_attachment=True,
        download_name=archivo["nombre_original"]
    )

@nube_bp.route('/tablero/nube/compartidos')
@login_required
def archivos_compartidos():
    """Ver todos los archivos compartidos públicamente por otros usuarios."""
    archivos = list(collection_nube.find({
        "compartido_publico": True,
        "usuario_id": {"$ne": current_user.id}
    }).sort("fecha_subida", -1))
    
    # Agregar información del propietario
    for archivo in archivos:
        propietario = collection_usuarios.find_one({"_id": ObjectId(archivo["usuario_id"])})
        if propietario:
            archivo["propietario_nombre"] = f"{propietario.get('nombres', '')} {propietario.get('apellidos', '')}"
            archivo["propietario_email"] = propietario.get('email', '')
    
    return render_template('nube_compartidos.html', archivos=archivos)