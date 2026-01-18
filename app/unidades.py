###
###
###  Este archivo contiene las rutas y funciones relacionadas con la visualización de 
###  eventos por unidades ejecutoras
### 
###
###
from flask import Flask, Blueprint, render_template, render_template_string, send_file, request, redirect, url_for, flash, abort
from app import db, collection_eventos, collection_participantes, collection_unidades, app
from flask_login import login_required, current_user
from datetime import datetime
from werkzeug.utils import secure_filename
from PIL import Image
from app.logs import log_event
import os

unidades_bp = Blueprint('unidades', __name__)


###
### Administracion de unidades ejecutoras
###
@unidades_bp.route('/tablero/unidades')
@login_required
def tablero_unidades():
    # Verificar si el usuario es administrador
    if current_user.rol != 'administrador':
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('home'))
    
    # Obtener todas las unidades ejecutoras
    unidades = list(collection_unidades.find().sort("nombre", 1))
    
    # Agregar URL de foto para cada unidad
    for unidad in unidades:
        if unidad.get('foto'):
            unidad['foto_url'] = f"/static/uploads/unidades/{unidad['foto']}"
        else:
            unidad['foto_url'] = "/static/uploads/unidades/default.jpg"
    
    return render_template('tablero_unidades.html', unidades=unidades)


###
### Crear nueva unidad ejecutora
###
@unidades_bp.route('/tablero/unidades/crear', methods=['POST'])
@login_required
def crear_unidad():
    # Verificar si el usuario es administrador
    if current_user.rol != 'administrador':
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('unidades.tablero_unidades'))
    
    try:
        # Obtener datos del formulario
        nombre = request.form.get('nombre', '').strip()
        slug = request.form.get('slug', '').strip()
        tipo = request.form.get('tipo', '').strip()
        provincia = request.form.get('provincia', '').strip()
        nivel_asistencial = int(request.form.get('nivel_asistencial', 1))
        formador_internos = request.form.get('formador_internos') == 'on'
        formador_residente = request.form.get('formador_residente') == 'on'
        activo = request.form.get('activo') == 'on'
        
        # Si es Coordinación Regional, forzar nivel 5
        if tipo == 'Coordinación Regional':
            nivel_asistencial = 5
        
        # Validar campos requeridos
        if not all([nombre, slug, tipo, provincia]):
            flash('Los campos nombre, slug, tipo y provincia son obligatorios.', 'error')
            return redirect(url_for('unidades.tablero_unidades'))
        
        # Verificar que el slug no exista
        if collection_unidades.find_one({"slug": slug}):
            flash('Ya existe una unidad con ese slug.', 'error')
            return redirect(url_for('unidades.tablero_unidades'))
        
        # Procesar imagen
        foto_filename = None
        foto_file = request.files.get('foto')
        if foto_file and foto_file.filename:
            if allowed_file(foto_file.filename):
                try:
                    # Crear directorio si no existe
                    unidades_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'unidades')
                    os.makedirs(unidades_dir, exist_ok=True)
                    
                    # Generar nombre de archivo
                    foto_filename = f"{slug}-{nivel_asistencial}.jpg"
                    foto_path = os.path.join(unidades_dir, foto_filename)
                    
                    # Debug: imprimir rutas
                    print(f"DEBUG: Guardando imagen en: {foto_path}")
                    print(f"DEBUG: Directorio existe: {os.path.exists(unidades_dir)}")
                    
                    # Procesar y guardar imagen usando PIL como en eventos
                    image = Image.open(foto_file)
                    if image.mode != 'RGB':
                        image = image.convert('RGB')
                    
                    # Redimensionar manteniendo aspecto (máximo 400x300)
                    image.thumbnail((400, 300), Image.Resampling.LANCZOS)
                    image.save(foto_path, 'JPEG', quality=85)
                    
                    # Verificar que se guardó
                    if os.path.exists(foto_path):
                        print(f"DEBUG: Imagen guardada exitosamente: {foto_path}")
                    else:
                        print(f"DEBUG: ERROR - Imagen no se guardó: {foto_path}")
                        foto_filename = None
                        
                except Exception as e:
                    print(f"DEBUG: Error al procesar imagen: {str(e)}")
                    flash(f'Error al procesar la imagen: {str(e)}', 'error')
                    foto_filename = None
            else:
                flash('Formato de imagen no válido. Use JPG, JPEG o PNG.', 'error')
                return redirect(url_for('unidades.tablero_unidades'))
        
        # Crear documento de unidad
        unidad_data = {
            'nombre': nombre,
            'slug': slug,
            'tipo': tipo,
            'provincia': provincia,
            'nivel_asistencial': nivel_asistencial,
            'formador_internos': formador_internos,
            'formador_residente': formador_residente,
            'activo': activo,
            'foto': foto_filename,
            'timestamp': datetime.now()
        }
        
        # Insertar en base de datos
        collection_unidades.insert_one(unidad_data)
        
        log_event(f"Usuario [{current_user.email}] creó la unidad ejecutora '{nombre}' (slug: {slug}).")
        flash(f'Unidad ejecutora "{nombre}" creada exitosamente.', 'success')
        
    except ValueError:
        flash('El nivel asistencial debe ser un número válido.', 'error')
    except Exception as e:
        flash(f'Error al crear la unidad: {str(e)}', 'error')
    
    return redirect(url_for('unidades.tablero_unidades'))


###
### Editar unidad ejecutora
###
@unidades_bp.route('/tablero/unidades/<unidad_id>/editar', methods=['GET', 'POST'])
@login_required
def editar_unidad(unidad_id):
    # Verificar si el usuario es administrador
    if current_user.rol != 'administrador':
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('unidades.tablero_unidades'))
    
    try:
        from bson.objectid import ObjectId
        
        # Buscar la unidad
        unidad = collection_unidades.find_one({"_id": ObjectId(unidad_id)})
        if not unidad:
            flash('Unidad no encontrada.', 'error')
            return redirect(url_for('unidades.tablero_unidades'))
        
        if request.method == 'POST':
            # Obtener datos del formulario
            nombre = request.form.get('nombre', '').strip()
            slug = request.form.get('slug', '').strip()
            tipo = request.form.get('tipo', '').strip()
            provincia = request.form.get('provincia', '').strip()
            nivel_asistencial = int(request.form.get('nivel_asistencial', 1))
            formador_internos = request.form.get('formador_internos') == 'on'
            formador_residente = request.form.get('formador_residente') == 'on'
            activo = request.form.get('activo') == 'on'
            
            # Si es Coordinación Regional, forzar nivel 5
            if tipo == 'Coordinación Regional':
                nivel_asistencial = 5
            
            # Validar campos requeridos
            if not all([nombre, slug, tipo, provincia]):
                flash('Los campos nombre, slug, tipo y provincia son obligatorios.', 'error')
                return redirect(url_for('unidades.editar_unidad', unidad_id=unidad_id))
            
            # Verificar que el slug no exista (excepto para la unidad actual)
            existing_unit = collection_unidades.find_one({"slug": slug, "_id": {"$ne": ObjectId(unidad_id)}})
            if existing_unit:
                flash('Ya existe otra unidad con ese slug.', 'error')
                return redirect(url_for('unidades.editar_unidad', unidad_id=unidad_id))
            
            # Procesar imagen si se subió una nueva
            foto_filename = unidad.get('foto')  # Mantener la foto actual por defecto
            foto_file = request.files.get('foto')
            if foto_file and foto_file.filename:
                if allowed_file(foto_file.filename):
                    try:
                        # Crear directorio si no existe
                        unidades_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'unidades')
                        os.makedirs(unidades_dir, exist_ok=True)
                        
                        # Eliminar foto anterior si existe y es diferente
                        if unidad.get('foto') and unidad['foto'] != 'default.jpg':
                            old_foto_path = os.path.join(unidades_dir, unidad['foto'])
                            if os.path.exists(old_foto_path):
                                os.remove(old_foto_path)
                        
                        # Generar nombre de archivo
                        foto_filename = f"{slug}-{nivel_asistencial}.jpg"
                        foto_path = os.path.join(unidades_dir, foto_filename)
                        
                        # Debug: imprimir rutas
                        print(f"DEBUG: Actualizando imagen en: {foto_path}")
                        print(f"DEBUG: Directorio existe: {os.path.exists(unidades_dir)}")
                        
                        # Procesar y guardar imagen usando PIL como en eventos
                        image = Image.open(foto_file)
                        if image.mode != 'RGB':
                            image = image.convert('RGB')
                        
                        # Redimensionar manteniendo aspecto (máximo 400x300)
                        image.thumbnail((400, 300), Image.Resampling.LANCZOS)
                        image.save(foto_path, 'JPEG', quality=85)
                        
                        # Verificar que se guardó
                        if os.path.exists(foto_path):
                            print(f"DEBUG: Imagen actualizada exitosamente: {foto_path}")
                        else:
                            print(f"DEBUG: ERROR - Imagen no se actualizó: {foto_path}")
                            foto_filename = unidad.get('foto')  # Mantener la anterior
                            
                    except Exception as e:
                        print(f"DEBUG: Error al procesar imagen en edición: {str(e)}")
                        flash(f'Error al procesar la imagen: {str(e)}', 'error')
                        foto_filename = unidad.get('foto')  # Mantener la anterior
                else:
                    flash('Formato de imagen no válido. Use JPG, JPEG o PNG.', 'error')
                    return redirect(url_for('unidades.editar_unidad', unidad_id=unidad_id))
            
            # Actualizar documento de unidad
            unidad_data = {
                'nombre': nombre,
                'slug': slug,
                'tipo': tipo,
                'provincia': provincia,
                'nivel_asistencial': nivel_asistencial,
                'formador_internos': formador_internos,
                'formador_residente': formador_residente,
                'activo': activo,
                'foto': foto_filename,
                'timestamp_updated': datetime.now()
            }
            
            # Actualizar en base de datos
            collection_unidades.update_one({"_id": ObjectId(unidad_id)}, {"$set": unidad_data})
            
            log_event(f"Usuario [{current_user.email}] editó la unidad ejecutora '{nombre}' (slug: {slug}).")
            flash(f'Unidad ejecutora "{nombre}" actualizada exitosamente.', 'success')
            return redirect(url_for('unidades.tablero_unidades'))
        
        # GET request - mostrar formulario de edición
        return render_template('editar_unidad.html', unidad=unidad)
        
    except ValueError:
        flash('El nivel asistencial debe ser un número válido.', 'error')
        return redirect(url_for('unidades.tablero_unidades'))
    except Exception as e:
        flash(f'Error al editar la unidad: {str(e)}', 'error')
        return redirect(url_for('unidades.tablero_unidades'))


###
### Eliminar unidad ejecutora
###
@unidades_bp.route('/tablero/unidades/<unidad_id>/eliminar', methods=['POST'])
@login_required
def eliminar_unidad(unidad_id):
    # Verificar si el usuario es administrador
    if current_user.rol != 'administrador':
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('unidades.tablero_unidades'))
    
    try:
        from bson.objectid import ObjectId
        
        # Buscar la unidad
        unidad = collection_unidades.find_one({"_id": ObjectId(unidad_id)})
        if not unidad:
            flash('Unidad no encontrada.', 'error')
            return redirect(url_for('unidades.tablero_unidades'))
        
        # Eliminar archivo de imagen si existe
        if unidad.get('foto'):
            foto_path = os.path.join(app.config['UPLOAD_FOLDER'], 'unidades', unidad['foto'])
            if os.path.exists(foto_path):
                os.remove(foto_path)
        
        # Eliminar de base de datos
        collection_unidades.delete_one({"_id": ObjectId(unidad_id)})
        
        log_event(f"Usuario [{current_user.email}] eliminó la unidad ejecutora '{unidad['nombre']}' (slug: {unidad.get('slug', 'N/A')}).")
        flash(f'Unidad "{unidad["nombre"]}" eliminada exitosamente.', 'success')
        
    except Exception as e:
        flash(f'Error al eliminar la unidad: {str(e)}', 'error')
    
    return redirect(url_for('unidades.tablero_unidades'))


###
### Función auxiliar para validar archivos
###
def allowed_file(filename):
    """Verifica si la extensión del archivo está permitida."""
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


###
### Catálogo de unidades ejecutoras
###
@unidades_bp.route('/catalogo/unidades')
def catalogo_unidades():
    # Obtener todas las unidades activas
    unidades = list(collection_unidades.find({"activo": True}).sort("nombre", 1))
    
    # Agregar URL de foto para cada unidad
    for unidad in unidades:
        if unidad.get('foto'):
            unidad['foto_url'] = f"/static/uploads/unidades/{unidad['foto']}"
        else:
            unidad['foto_url'] = "/static/uploads/unidades/default.jpg"
    
    return render_template('catalogo_unidades.html', unidades=unidades)


###
### Docencia semanal por unidad específica
###
@unidades_bp.route('/catalogo/unidades/<codigo_unidad>')
@unidades_bp.route('/catalogo/unidades/<codigo_unidad>/page/<int:page>')
def docencia_unidad(codigo_unidad, page=1):
    # Buscar la unidad por slug
    unidad = collection_unidades.find_one({"slug": codigo_unidad, "activo": True})
    
    if not unidad:
        # Si no se encuentra la unidad, mostrar página de error o redirigir
        flash('Unidad no encontrada.', 'error')
        return redirect(url_for('unidades.catalogo_unidades'))
    
    # Agregar URL de foto
    if unidad.get('foto'):
        unidad['foto_url'] = f"/static/uploads/unidades/{unidad['foto']}"
    else:
        unidad['foto_url'] = "/static/uploads/unidades/default.jpg"
    
    # Configuración de paginación
    per_page = 15  # Número máximo de eventos por página
    skip = (page - 1) * per_page

    # Filtro para eventos de tipo "Sesión Docente" de esta unidad
    # El campo 'nombre' de la unidad debe coincidir con 'unidad_ejecutora' del evento
    
    # Enfoque 1: Coincidencia exacta
    filtro_exacto = {
        "estado_evento": {"$ne": "borrador"},
        'tipo': 'Sesión Docente',
        'unidad_ejecutora': unidad['nombre']
    }
    
    # Enfoque 2: Coincidencia con regex (case-insensitive y trimming)
    import re
    nombre_unidad_regex = re.compile(f"^{re.escape(unidad['nombre'].strip())}$", re.IGNORECASE)
    filtro_regex = {
        "estado_evento": {"$ne": "borrador"},
        'tipo': 'Sesión Docente',
        'unidad_ejecutora': nombre_unidad_regex
    }
    
    # Usar el filtro exacto primero, luego regex si no hay resultados
    filtro_docencia = filtro_exacto

    # Contar total de eventos de docencia
    total_eventos = collection_eventos.count_documents(filtro_docencia)
    
    # Si no hay resultados con filtro exacto, probar con regex
    if total_eventos == 0:
        filtro_docencia = filtro_regex
        total_eventos = collection_eventos.count_documents(filtro_docencia)
    
    total_pages = (total_eventos + per_page - 1) // per_page if total_eventos > 0 else 1

    # Verificar si la página solicitada es válida
    if page < 1 or (total_eventos > 0 and page > total_pages):
        abort(404)

    # Obtener eventos paginados
    eventos = list(collection_eventos.find(filtro_docencia).sort("fecha_inicio", -1).skip(skip).limit(per_page))
    
    return render_template('catalogo_unidad.html', 
                         codigo_unidad=codigo_unidad, 
                         unidad=unidad, 
                         eventos=eventos,
                         page=page,
                         total_pages=total_pages,
                         total_eventos=total_eventos)