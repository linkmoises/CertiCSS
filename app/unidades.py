###
###
###  Este archivo contiene las rutas y funciones relacionadas con la visualización de 
###  eventos por unidades ejecutoras
### 
###
###
from flask import Flask, Blueprint, render_template, render_template_string, send_file, request, redirect, url_for, flash, abort, jsonify
from app import db, collection_eventos, collection_participantes, collection_unidades, collection_usuarios, collection_renombramientos, app
from flask_login import login_required, current_user
from datetime import datetime
from werkzeug.utils import secure_filename
from PIL import Image
from app.logs import log_event
from app.helpers import allowed_file_images as allowed_file
from app.unidades_data import (
    PROVINCIA_A_REGION,
    REGION_A_CSS,
    CSS_A_REGION,
    REGION_LABEL,
    region_de_unidad,
    region_usuario_de_unidad,
    invalidar_cache_unidades,
    resolver_unidad,
    nombres_equivalentes,
    slugify,
    arbol_administrativas,
    aplanar_arbol,
    descendientes_administrativas,
    unidad_puede_ser_padre,
)
from app.unidades_normalizacion import (
    detectar_renombramientos,
    revisar_renombramiento,
    aplicar_renombramiento,
    resumen_huerfanos,
    validar_colisiones,
    generar_respaldo,
)
import os
import re
import json
import io
from bson.objectid import ObjectId
from bson import json_util

unidades_bp = Blueprint('unidades', __name__)


def _parse_nombres_anteriores(texto):
    """Convierte un textarea (líneas, comas o punto y coma) en lista de aliases limpia."""
    if not texto:
        return []
    partes = re.split(r'[\n,;]+', texto)
    vistos = set()
    resultado = []
    for parte in partes:
        limpio = parte.strip()
        if limpio and limpio not in vistos:
            vistos.add(limpio)
            resultado.append(limpio)
    return resultado


def _alias_ocupado(nombres_anteriores, excluir_id=None):
    """Devuelve el primer alias que ya exista como nombre canónico de otra unidad."""
    if not nombres_anteriores:
        return None
    filtro = {"nombre": {"$in": nombres_anteriores}}
    if excluir_id is not None:
        filtro["_id"] = {"$ne": excluir_id}
    doc = collection_unidades.find_one(filtro)
    return doc['nombre'] if doc else None


def _guardar_foto_unidad(foto_file, slug, foto_actual=None):
    """Guarda y redimensiona la foto/logo de una unidad. Devuelve el nombre de archivo."""
    if not foto_file or not foto_file.filename:
        return foto_actual
    if not allowed_file(foto_file.filename):
        raise ValueError('Formato de imagen no válido. Use JPG, JPEG o PNG.')
    unidades_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'unidades')
    os.makedirs(unidades_dir, exist_ok=True)
    if foto_actual and foto_actual != 'default.jpg':
        old_foto_path = os.path.join(unidades_dir, foto_actual)
        if os.path.exists(old_foto_path):
            os.remove(old_foto_path)
    foto_filename = f"{slug}.jpg"
    foto_path = os.path.join(unidades_dir, foto_filename)
    image = Image.open(foto_file)
    if image.mode != 'RGB':
        image = image.convert('RGB')
    image.thumbnail((400, 300), Image.Resampling.LANCZOS)
    image.save(foto_path, 'JPEG', quality=85)
    if os.path.exists(foto_path):
        return foto_filename
    return foto_actual


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
    
    # Obtener todas las unidades ejecutoras (excluye unidades administrativas)
    unidades = list(collection_unidades.find({"categoria": {"$ne": "administrativa"}}).sort([
        ("nivel_asistencial", -1),    # Nivel asistencial descendente (5,4,3,2,1)
        ("nivel_complejidad", -1),    # Nivel complejidad descendente (9,8,7,6...)
        ("nombre", 1)                 # Nombre alfabético ascendente (A-Z)
    ]))
    
    # Agregar URL de foto para cada unidad
    for unidad in unidades:
        if unidad.get('foto'):
            unidad['foto_url'] = f"/static/uploads/unidades/{unidad['foto']}"
        else:
            unidad['foto_url'] = "/static/assets/unidades/default.jpg"
        unidad['region'] = region_de_unidad(unidad)

    # Lista serializable (solo nombre + región) para el JS de sugerencia de slug
    unidades_existentes = [
        {'nombre': u.get('nombre'), 'region': u.get('region')}
        for u in unidades
    ]

    return render_template('tablero_unidades.html', unidades=unidades,
                           unidades_existentes=unidades_existentes)


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
        region = request.form.get('region', '').strip()
        nivel_asistencial = int(request.form.get('nivel_asistencial', 1))
        nivel_complejidad = request.form.get('nivel_complejidad', '').strip()
        formador_internos = request.form.get('formador_internos') == 'on'
        formador_residente = request.form.get('formador_residente') == 'on'
        activo = request.form.get('activo') == 'on'
        nombres_anteriores = _parse_nombres_anteriores(request.form.get('nombres_anteriores', ''))
        
        # Obtener coordenadas geográficas
        latitud = request.form.get('latitud', '').strip()
        longitud = request.form.get('longitud', '').strip()
        altitud = request.form.get('altitud', '').strip()
        
        # Convertir coordenadas a float si están presentes
        latitud = float(latitud) if latitud else None
        longitud = float(longitud) if longitud else None
        altitud = int(altitud) if altitud else None
        
        # Si es Coordinación Regional, forzar nivel 5 y complejidad NA
        if tipo == 'Coordinación Regional':
            nivel_asistencial = 5
            nivel_complejidad = 'NA'
        else:
            nivel_complejidad = int(request.form.get('nivel_complejidad', 1))
        
        # Validar campos requeridos
        if not all([nombre, slug, tipo, provincia]):
            flash('Los campos nombre, slug, tipo y provincia son obligatorios.', 'error')
            return redirect(url_for('unidades.tablero_unidades'))
        
        # Verificar que el slug no exista
        if collection_unidades.find_one({"slug": slug}):
            flash('Ya existe una unidad con ese slug.', 'error')
            return redirect(url_for('unidades.tablero_unidades'))
        
        # Región derivada
        region_final = region or PROVINCIA_A_REGION.get(provincia, 'panama')
        
        # Validar colisión del nombre canónico dentro de la misma región
        if collection_unidades.find_one({"nombre": nombre, "region": region_final}):
            flash(f'Ya existe una unidad llamada "{nombre}" en la región {REGION_LABEL.get(region_final, region_final)}.', 'error')
            return redirect(url_for('unidades.tablero_unidades'))
        
        # Validar que los aliases no estén tomados como nombre canónico por otra unidad
        alias_ocupado = _alias_ocupado(nombres_anteriores)
        if alias_ocupado:
            flash(f'El alias "{alias_ocupado}" ya está registrado como nombre de otra unidad.', 'error')
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
            'categoria': 'regional' if tipo == 'Coordinación Regional' else 'asistencial',
            'region': region or PROVINCIA_A_REGION.get(provincia, 'panama'),
            'region_usuario': REGION_A_CSS.get(region or PROVINCIA_A_REGION.get(provincia, 'panama'), 'css00'),
            'nombres_anteriores': nombres_anteriores,
            'nivel_asistencial': nivel_asistencial,
            'nivel_complejidad': nivel_complejidad,
            'formador_internos': formador_internos,
            'formador_residente': formador_residente,
            'activo': activo,
            'foto': foto_filename,
            'latitud': latitud,
            'longitud': longitud,
            'altitud': altitud,
            'timestamp': datetime.now()
        }
        
        # Insertar en base de datos
        collection_unidades.insert_one(unidad_data)
        
        invalidar_cache_unidades()
        
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
            region = request.form.get('region', '').strip()
            nivel_asistencial = int(request.form.get('nivel_asistencial', 1))
            nivel_complejidad = request.form.get('nivel_complejidad', '').strip()
            formador_internos = request.form.get('formador_internos') == 'on'
            formador_residente = request.form.get('formador_residente') == 'on'
            activo = request.form.get('activo') == 'on'
            nombres_anteriores = _parse_nombres_anteriores(request.form.get('nombres_anteriores', ''))
            
            # Obtener coordenadas geográficas
            latitud = request.form.get('latitud', '').strip()
            longitud = request.form.get('longitud', '').strip()
            altitud = request.form.get('altitud', '').strip()
            
            # Convertir coordenadas a float si están presentes
            latitud = float(latitud) if latitud else None
            longitud = float(longitud) if longitud else None
            altitud = int(altitud) if altitud else None
            
            # Si es Coordinación Regional, forzar nivel 5 y complejidad NA
            if tipo == 'Coordinación Regional':
                nivel_asistencial = 5
                nivel_complejidad = 'NA'
            else:
                nivel_complejidad = int(request.form.get('nivel_complejidad', 1))
            
            # Validar campos requeridos
            if not all([nombre, slug, tipo, provincia]):
                flash('Los campos nombre, slug, tipo y provincia son obligatorios.', 'error')
                return redirect(url_for('unidades.editar_unidad', unidad_id=unidad_id))
            
            # Verificar que el slug no exista (excepto para la unidad actual)
            existing_unit = collection_unidades.find_one({"slug": slug, "_id": {"$ne": ObjectId(unidad_id)}})
            if existing_unit:
                flash('Ya existe otra unidad con ese slug.', 'error')
                return redirect(url_for('unidades.editar_unidad', unidad_id=unidad_id))
            
            # Región derivada
            region_final = region or PROVINCIA_A_REGION.get(provincia, 'panama')
            
            # Validar colisión del nombre canónico dentro de la misma región
            if collection_unidades.find_one({"nombre": nombre, "region": region_final, "_id": {"$ne": ObjectId(unidad_id)}}):
                flash(f'Ya existe una unidad llamada "{nombre}" en la región {REGION_LABEL.get(region_final, region_final)}.', 'error')
                return redirect(url_for('unidades.editar_unidad', unidad_id=unidad_id))
            
            # Validar que los aliases no estén tomados como nombre canónico por otra unidad
            alias_ocupado = _alias_ocupado(nombres_anteriores, excluir_id=ObjectId(unidad_id))
            if alias_ocupado:
                flash(f'El alias "{alias_ocupado}" ya está registrado como nombre de otra unidad.', 'error')
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
                'categoria': 'regional' if tipo == 'Coordinación Regional' else 'asistencial',
                'region': region or PROVINCIA_A_REGION.get(provincia, 'panama'),
                'region_usuario': REGION_A_CSS.get(region or PROVINCIA_A_REGION.get(provincia, 'panama'), 'css00'),
                'nombres_anteriores': nombres_anteriores,
                'nivel_asistencial': nivel_asistencial,
                'nivel_complejidad': nivel_complejidad,
                'formador_internos': formador_internos,
                'formador_residente': formador_residente,
                'activo': activo,
                'foto': foto_filename,
                'latitud': latitud,
                'longitud': longitud,
                'altitud': altitud,
                'timestamp_updated': datetime.now()
            }
            
            # Actualizar en base de datos
            collection_unidades.update_one({"_id": ObjectId(unidad_id)}, {"$set": unidad_data})
            
            invalidar_cache_unidades()
            
            log_event(f"Usuario [{current_user.email}] editó la unidad ejecutora '{nombre}' (slug: {slug}).")
            flash(f'Unidad ejecutora "{nombre}" actualizada exitosamente.', 'success')
            return redirect(url_for('unidades.tablero_unidades'))
        
        # GET request - mostrar formulario de edición
        return render_template('editar_unidad.html', unidad=unidad, region_actual=region_de_unidad(unidad))
        
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
        
        invalidar_cache_unidades()
        
        log_event(f"Usuario [{current_user.email}] eliminó la unidad ejecutora '{unidad['nombre']}' (slug: {unidad.get('slug', 'N/A')}).")
        flash(f'Unidad "{unidad["nombre"]}" eliminada exitosamente.', 'success')
        
    except Exception as e:
        flash(f'Error al eliminar la unidad: {str(e)}', 'error')
    
    return redirect(url_for('unidades.tablero_unidades'))


###
### Catálogo de unidades ejecutoras
###
@unidades_bp.route('/catalogo/unidades')
def catalogo_unidades():
    # Obtener todas las unidades activas (excluye unidades administrativas)
    unidades = list(collection_unidades.find({"activo": True, "categoria": {"$ne": "administrativa"}}).sort([
        ("nivel_asistencial", -1),    # Nivel asistencial descendente (5,4,3,2,1)
        ("nivel_complejidad", -1),    # Nivel complejidad descendente (9,8,7,6...)
        ("nombre", 1)                 # Nombre alfabético ascendente (A-Z)
    ]))
    
    # Agregar URL de foto y coordinador para cada unidad
    for unidad in unidades:
        # Agregar URL de foto
        if unidad.get('foto'):
            unidad['foto_url'] = f"/static/uploads/unidades/{unidad['foto']}"
        else:
            unidad['foto_url'] = "/static/assets/unidades/default.jpg"
        
        # Buscar coordinador de docencia para esta unidad
        # Solo buscar usuarios con roles específicos que son únicos por unidad:
        # coordinador-regional, coordinador-local, subdirector-docencia
        # Se buscan nombre canónico + aliases (nombres_anteriores) y se restringe
        # a la región del usuario (cssNN) para resolver unidades homónimas.
        coordinador = None

        # Enfoque 1: Buscar coordinador local específico para esta unidad
        coordinador = collection_usuarios.find_one({
            "unidad_ejecutora": {"$in": nombres_equivalentes(unidad)},
            "region": region_usuario_de_unidad(unidad),
            "rol": "coordinador-local",
            "activo": True
        })
        
        # Enfoque 2: Si no hay coordinador local, buscar subdirector de docencia
        if not coordinador:
            coordinador = collection_usuarios.find_one({
                "unidad_ejecutora": {"$in": nombres_equivalentes(unidad)},
                "region": region_usuario_de_unidad(unidad),
                "rol": "subdirector-docencia",
                "activo": True
            })
        
        # Enfoque 3: Si no hay subdirector, buscar coordinador regional
        if not coordinador:
            coordinador = collection_usuarios.find_one({
                "unidad_ejecutora": {"$in": nombres_equivalentes(unidad)},
                "region": region_usuario_de_unidad(unidad),
                "rol": "coordinador-regional",
                "activo": True
            })
        
        # Enfoque 4: Si no hay coincidencia exacta, probar sin restricción de región
        # pero solo para los roles permitidos
        if not coordinador:
            coordinador = collection_usuarios.find_one({
                "unidad_ejecutora": {"$in": nombres_equivalentes(unidad)},
                "rol": {"$in": ["coordinador-local", "subdirector-docencia", "coordinador-regional"]},
                "activo": True
            })
        
        if coordinador:
            # Construir nombre completo del coordinador
            nombre_completo = f"{coordinador.get('nombres', '')} {coordinador.get('apellidos', '')}".strip()
            unidad['coordinador_nombre'] = nombre_completo if nombre_completo else 'No asignado'
            
            # Agregar rol del coordinador (solo los roles permitidos)
            rol_coordinador = coordinador.get('rol', '')
            rol_legible = {
                'coordinador-local': 'Coordinador Local de Docencia e Investigación',
                'coordinador-regional': 'Coordinador Regional de Docencia',
                'subdirector-docencia': 'Subdirector de Docencia e Investigación'
            }.get(rol_coordinador, 'Rol no válido')
            
            unidad['coordinador_rol'] = rol_legible
        else:
            unidad['coordinador_nombre'] = 'Designación/asociación pendiente'
            unidad['coordinador_rol'] = 'Coordinador Local'
    
    return render_template('catalogo_unidades.html', unidades=unidades)


###
### Docencia semanal por unidad específica
###
@unidades_bp.route('/catalogo/unidades/<codigo_unidad>')
@unidades_bp.route('/catalogo/unidades/<codigo_unidad>/page/<int:page>')
def docencia_unidad(codigo_unidad, page=1):
    # Buscar la unidad por slug (excluye unidades administrativas)
    unidad = collection_unidades.find_one({"slug": codigo_unidad, "activo": True, "categoria": {"$ne": "administrativa"}})
    
    if not unidad:
        # Si no se encuentra la unidad, mostrar página de error o redirigir
        flash('Unidad no encontrada.', 'error')
        return redirect(url_for('unidades.catalogo_unidades'))
    
    # Agregar URL de foto
    if unidad.get('foto'):
        unidad['foto_url'] = f"/static/uploads/unidades/{unidad['foto']}"
    else:
        unidad['foto_url'] = "/static/assets/unidades/default.jpg"
    
    # Configuración de paginación
    per_page = 15  # Número máximo de eventos por página
    skip = (page - 1) * per_page

    # Filtro para eventos de tipo "Sesión Docente" de esta unidad
    # Se buscan el nombre canónico y los aliases históricos (nombres_anteriores)
    # y se restringe a la región de la unidad para evitar colisiones homónimas.
    nombres_busqueda = nombres_equivalentes(unidad)
    region_eventos = region_de_unidad(unidad)
    filtro_docencia = {
        "estado_evento": {"$ne": "borrador"},
        'tipo': 'Sesión Docente',
        'unidad_ejecutora': {"$in": nombres_busqueda}
    }
    if region_eventos:
        filtro_docencia['region'] = region_eventos

    # Contar total de eventos de docencia
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


def _backfill_slugs_administrativas():
    """Backfill de slugs faltantes en unidades administrativas (creadas sin slug)."""
    docs = list(collection_unidades.find({"categoria": "administrativa", "slug": None}))
    for doc in docs:
        base = slugify(doc.get('nombre') or 'unidad')
        slug = base
        contador = 2
        while collection_unidades.find_one({"slug": slug, "_id": {"$ne": doc['_id']}}):
            slug = f"{base}-{contador}"
            contador += 1
        collection_unidades.update_one({"_id": doc['_id']}, {"$set": {"slug": slug}})


###
### Catálogo de unidades administrativas (índice en árbol)
###
@unidades_bp.route('/catalogo/unidades-administrativas')
def catalogo_unidades_administrativas():
    _backfill_slugs_administrativas()
    
    # Índice en árbol de administrativas activas
    unidades_arbol = [(doc, nivel) for doc, nivel in aplanar_arbol(arbol_administrativas())
                      if doc.get('activo', True)]
    
    # Contar dependientes y agregar URL de logo
    conteo_dependientes = {}
    for doc, _nivel in unidades_arbol:
        conteo_dependientes[str(doc['_id'])] = len(descendientes_administrativas(doc['_id']))
        if doc.get('foto'):
            doc['foto_url'] = f"/static/uploads/unidades/{doc['foto']}"
        else:
            doc['foto_url'] = "/static/assets/unidades/default.jpg"
    
    return render_template('catalogo_unidades_administrativas.html',
                           unidades=unidades_arbol,
                           conteo_dependientes=conteo_dependientes)


###
### Docencia de una unidad administrativa específica
###
@unidades_bp.route('/catalogo/unidades-administrativas/<slug>')
@unidades_bp.route('/catalogo/unidades-administrativas/<slug>/page/<int:page>')
def docencia_unidad_administrativa(slug, page=1):
    unidad = collection_unidades.find_one({"slug": slug, "categoria": "administrativa", "activo": True})
    
    if not unidad:
        flash('Unidad administrativa no encontrada.', 'error')
        return redirect(url_for('unidades.catalogo_unidades_administrativas'))
    
    if unidad.get('foto'):
        unidad['foto_url'] = f"/static/uploads/unidades/{unidad['foto']}"
    else:
        unidad['foto_url'] = "/static/assets/unidades/default.jpg"
    
    # Configuración de paginación
    per_page = 15
    skip = (page - 1) * per_page
    
    # Docencia: match por nombre canónico + aliases, SIN restricción de región
    # (todas comparten "administrativas"; robusto ante eventos históricos con otra región)
    nombres_busqueda = nombres_equivalentes(unidad)
    filtro_docencia = {
        "estado_evento": {"$ne": "borrador"},
        'tipo': 'Sesión Docente',
        'unidad_ejecutora': {"$in": nombres_busqueda}
    }
    
    total_eventos = collection_eventos.count_documents(filtro_docencia)
    total_pages = (total_eventos + per_page - 1) // per_page if total_eventos > 0 else 1
    
    if page < 1 or (total_eventos > 0 and page > total_pages):
        abort(404)
    
    eventos = list(collection_eventos.find(filtro_docencia).sort("fecha_inicio", -1).skip(skip).limit(per_page))
    
    return render_template('catalogo_unidad.html', 
                         codigo_unidad=slug, 
                         unidad=unidad, 
                         eventos=eventos,
                         page=page,
                         total_pages=total_pages,
                         total_eventos=total_eventos)


###
### Administración de unidades administrativas
###
@unidades_bp.route('/tablero/unidades-administrativas')
@login_required
def tablero_unidades_administrativas():
    # Verificar si el usuario es administrador
    if current_user.rol != 'administrador':
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('home'))
    
    # Obtener unidades administrativas en orden estructural (padres primero)
    unidades_arbol = aplanar_arbol(arbol_administrativas())
    
    # Contar dependientes de cada unidad
    dependientes = {}
    for doc, _nivel in unidades_arbol:
        dependientes[str(doc['_id'])] = len(descendientes_administrativas(doc['_id']))
    
    return render_template('tablero_unidades_administrativas.html',
                           unidades=unidades_arbol,
                           conteo_dependientes=dependientes)


###
### Crear unidad administrativa
###
@unidades_bp.route('/tablero/unidades-administrativas/crear', methods=['POST'])
@login_required
def crear_unidad_administrativa():
    if current_user.rol != 'administrador':
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('unidades.tablero_unidades_administrativas'))
    
    try:
        nombre = request.form.get('nombre', '').strip()
        slug = request.form.get('slug', '').strip()
        tipo = request.form.get('tipo', '').strip()
        activo = request.form.get('activo') == 'on'
        unidad_padre = request.form.get('unidad_padre', '').strip()
        nombres_anteriores = _parse_nombres_anteriores(request.form.get('nombres_anteriores', ''))
        
        if not all([nombre, tipo]):
            flash('Los campos nombre y tipo son obligatorios.', 'error')
            return redirect(url_for('unidades.tablero_unidades_administrativas'))
        
        if collection_unidades.find_one({"nombre": nombre, "categoria": "administrativa"}):
            flash('Ya existe una unidad administrativa con ese nombre.', 'error')
            return redirect(url_for('unidades.tablero_unidades_administrativas'))
        
        # Validar padre (solo administrativas; no a sí misma ni descendiente — no aplica en creación)
        padre_id = None
        if unidad_padre:
            if not ObjectId.is_valid(unidad_padre):
                flash('El padre seleccionado no es válido.', 'error')
                return redirect(url_for('unidades.tablero_unidades_administrativas'))
            padre = collection_unidades.find_one({"_id": ObjectId(unidad_padre), "categoria": "administrativa"})
            if not padre:
                flash('El padre seleccionado debe ser una unidad administrativa.', 'error')
                return redirect(url_for('unidades.tablero_unidades_administrativas'))
            padre_id = ObjectId(unidad_padre)
        
        # Slug: autogenerar si viene vacío (sin prefijo de región para administrativas)
        if not slug:
            slug = slugify(nombre)
            base_slug = slug
            contador = 2
            while collection_unidades.find_one({"slug": slug}):
                slug = f"{base_slug}-{contador}"
                contador += 1
        
        # Validar que los aliases no estén tomados como nombre canónico por otra unidad
        alias_ocupado = _alias_ocupado(nombres_anteriores)
        if alias_ocupado:
            flash(f'El alias "{alias_ocupado}" ya está registrado como nombre de otra unidad.', 'error')
            return redirect(url_for('unidades.tablero_unidades_administrativas'))
        
        # Procesar foto (logo)
        foto_filename = _guardar_foto_unidad(request.files.get('foto'), slug)
        
        unidad_data = {
            'nombre': nombre,
            'slug': slug,
            'tipo': tipo,
            'categoria': 'administrativa',
            'region': 'administrativas',
            'region_usuario': 'css00',
            'unidad_padre': padre_id,
            'nombres_anteriores': nombres_anteriores,
            'foto': foto_filename,
            'activo': activo,
            'timestamp': datetime.now()
        }
        
        collection_unidades.insert_one(unidad_data)
        
        invalidar_cache_unidades()
        
        log_event(f"Usuario [{current_user.email}] creó la unidad administrativa '{nombre}' (slug: {slug}).")
        flash(f'Unidad administrativa "{nombre}" creada exitosamente.', 'success')
        
    except Exception as e:
        flash(f'Error al crear la unidad administrativa: {str(e)}', 'error')
    
    return redirect(url_for('unidades.tablero_unidades_administrativas'))


###
### Editar unidad administrativa
###
@unidades_bp.route('/tablero/unidades-administrativas/<unidad_id>/editar', methods=['GET', 'POST'])
@login_required
def editar_unidad_administrativa(unidad_id):
    if current_user.rol != 'administrador':
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('unidades.tablero_unidades_administrativas'))
    
    try:
        from bson.objectid import ObjectId
        
        unidad = collection_unidades.find_one({"_id": ObjectId(unidad_id)})
        if not unidad:
            flash('Unidad administrativa no encontrada.', 'error')
            return redirect(url_for('unidades.tablero_unidades_administrativas'))
        
        if request.method == 'POST':
            nombre = request.form.get('nombre', '').strip()
            slug = request.form.get('slug', '').strip()
            tipo = request.form.get('tipo', '').strip()
            activo = request.form.get('activo') == 'on'
            unidad_padre = request.form.get('unidad_padre', '').strip()
            nombres_anteriores = _parse_nombres_anteriores(request.form.get('nombres_anteriores', ''))
            
            if not all([nombre, tipo]):
                flash('Los campos nombre y tipo son obligatorios.', 'error')
                return redirect(url_for('unidades.editar_unidad_administrativa', unidad_id=unidad_id))
            
            existing = collection_unidades.find_one({
                "nombre": nombre,
                "categoria": "administrativa",
                "_id": {"$ne": ObjectId(unidad_id)}
            })
            if existing:
                flash('Ya existe otra unidad administrativa con ese nombre.', 'error')
                return redirect(url_for('unidades.editar_unidad_administrativa', unidad_id=unidad_id))
            
            # Validar padre: solo administrativas y sin ciclos (ni a sí misma ni a un descendiente)
            padre_id = None
            if unidad_padre:
                if not ObjectId.is_valid(unidad_padre):
                    flash('El padre seleccionado no es válido.', 'error')
                    return redirect(url_for('unidades.editar_unidad_administrativa', unidad_id=unidad_id))
                padre = collection_unidades.find_one({"_id": ObjectId(unidad_padre), "categoria": "administrativa"})
                if not padre:
                    flash('El padre seleccionado debe ser una unidad administrativa.', 'error')
                    return redirect(url_for('unidades.editar_unidad_administrativa', unidad_id=unidad_id))
                if not unidad_puede_ser_padre(ObjectId(unidad_id), ObjectId(unidad_padre)):
                    flash('El padre seleccionado crearía un ciclo jerárquico (la unidad o un descendiente ya dependen de él).', 'error')
                    return redirect(url_for('unidades.editar_unidad_administrativa', unidad_id=unidad_id))
                padre_id = ObjectId(unidad_padre)
            
            # Slug: autogenerar si viene vacío (sin prefijo de región para administrativas)
            if not slug:
                slug = slugify(nombre)
                base_slug = slug
                contador = 2
                while collection_unidades.find_one({"slug": slug, "_id": {"$ne": ObjectId(unidad_id)}}):
                    slug = f"{base_slug}-{contador}"
                    contador += 1
            else:
                otro_con_slug = collection_unidades.find_one({"slug": slug, "_id": {"$ne": ObjectId(unidad_id)}})
                if otro_con_slug:
                    flash('Ya existe otra unidad con ese slug.', 'error')
                    return redirect(url_for('unidades.editar_unidad_administrativa', unidad_id=unidad_id))
            
            # Validar que los aliases no estén tomados como nombre canónico por otra unidad
            alias_ocupado = _alias_ocupado(nombres_anteriores, excluir_id=ObjectId(unidad_id))
            if alias_ocupado:
                flash(f'El alias "{alias_ocupado}" ya está registrado como nombre de otra unidad.', 'error')
                return redirect(url_for('unidades.editar_unidad_administrativa', unidad_id=unidad_id))
            
            # Procesar foto (logo)
            foto_filename = _guardar_foto_unidad(request.files.get('foto'), slug, foto_actual=unidad.get('foto'))
            
            collection_unidades.update_one({"_id": ObjectId(unidad_id)}, {"$set": {
                'nombre': nombre,
                'slug': slug,
                'tipo': tipo,
                'categoria': 'administrativa',
                'region': 'administrativas',
                'region_usuario': 'css00',
                'unidad_padre': padre_id,
                'nombres_anteriores': nombres_anteriores,
                'foto': foto_filename,
                'activo': activo,
                'timestamp_updated': datetime.now()
            }})
            
            invalidar_cache_unidades()
            
            log_event(f"Usuario [{current_user.email}] editó la unidad administrativa '{nombre}' (slug: {slug}).")
            flash(f'Unidad administrativa "{nombre}" actualizada exitosamente.', 'success')
            return redirect(url_for('unidades.tablero_unidades_administrativas'))
        
        # Lista de padres posibles: administrativas, excluyendo a la unidad y sus descendientes
        opciones_padre = [
            (doc, nivel) for doc, nivel in aplanar_arbol(arbol_administrativas())
            if unidad_puede_ser_padre(ObjectId(unidad_id), doc['_id'])
        ]
        return render_template('editar_unidad_administrativa.html', unidad=unidad, opciones_padre=opciones_padre)
        
    except Exception as e:
        flash(f'Error al editar la unidad administrativa: {str(e)}', 'error')
        return redirect(url_for('unidades.tablero_unidades_administrativas'))


###
### Eliminar unidad administrativa
###
@unidades_bp.route('/tablero/unidades-administrativas/<unidad_id>/eliminar', methods=['POST'])
@login_required
def eliminar_unidad_administrativa(unidad_id):
    if current_user.rol != 'administrador':
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('unidades.tablero_unidades_administrativas'))
    
    try:
        from bson.objectid import ObjectId
        
        unidad = collection_unidades.find_one({"_id": ObjectId(unidad_id)})
        if not unidad:
            flash('Unidad administrativa no encontrada.', 'error')
            return redirect(url_for('unidades.tablero_unidades_administrativas'))
        
        nombre = unidad['nombre']
        nombres_busqueda = nombres_equivalentes(unidad)
        region_ev = region_de_unidad(unidad)
        region_usr = REGION_A_CSS.get(region_ev) if region_ev else None
        
        # Bloqueado si tiene dependientes (hay que reasignarlos o eliminarlos antes)
        dependientes = descendientes_administrativas(unidad['_id'])
        if dependientes:
            hijos = collection_unidades.find(
                {"unidad_padre": ObjectId(unidad_id)},
                {"nombre": 1}
            )
            nombres_hijos = [h['nombre'] for h in hijos]
            lista_hijos = ', '.join(nombres_hijos) if nombres_hijos else 'dependientes (nivel inferior)'
            flash(f'No se puede eliminar "{nombre}": reasigne o elimine primero sus dependientes: {lista_hijos}.', 'error')
            return redirect(url_for('unidades.tablero_unidades_administrativas'))
        
        # Reporte de referencias (no bloquea la eliminación)
        # Cuenta también los aliases históricos y restringe por región.
        filtro_eventos = {"unidad_ejecutora": {"$in": nombres_busqueda}}
        filtro_usuarios = {"unidad_ejecutora": {"$in": nombres_busqueda}}
        filtro_participantes = {"unidad": {"$in": nombres_busqueda}}
        if region_ev:
            filtro_eventos['region'] = region_ev
            filtro_participantes['region'] = region_ev
        if region_usr:
            filtro_usuarios['region'] = region_usr
        refs_eventos = collection_eventos.count_documents(filtro_eventos)
        refs_usuarios = collection_usuarios.count_documents(filtro_usuarios)
        refs_participantes = collection_participantes.count_documents(filtro_participantes)
        
        collection_unidades.delete_one({"_id": ObjectId(unidad_id)})
        
        invalidar_cache_unidades()
        
        log_event(f"Usuario [{current_user.email}] eliminó la unidad administrativa '{nombre}'.")
        if refs_eventos or refs_usuarios or refs_participantes:
            flash(f'Unidad administrativa "{nombre}" eliminada. Referencias: {refs_eventos} eventos, {refs_usuarios} usuarios, {refs_participantes} participantes.', 'warning')
        else:
            flash(f'Unidad administrativa "{nombre}" eliminada exitosamente.', 'success')
        
    except Exception as e:
        flash(f'Error al eliminar la unidad administrativa: {str(e)}', 'error')
    
    return redirect(url_for('unidades.tablero_unidades_administrativas'))


###
### Normalización de renombramientos históricos de unidades
###
def _conteos_renombramiento(doc):
    nombre = (doc.get('nombre_anterior') or '').strip()
    region = doc.get('region')
    region_usuario = REGION_A_CSS.get(region) if region else None
    filtro_eventos = {'unidad_ejecutora': nombre}
    filtro_participantes = {'unidad': nombre}
    filtro_usuarios = {'unidad_ejecutora': nombre}
    if region:
        filtro_eventos['region'] = region
        filtro_participantes['region'] = region
    if region_usuario:
        filtro_usuarios['region'] = region_usuario
    return {
        'eventos': collection_eventos.count_documents(filtro_eventos),
        'participantes': collection_participantes.count_documents(filtro_participantes),
        'usuarios': collection_usuarios.count_documents(filtro_usuarios),
    }


def _renombramientos_con_conteos():
    docs = list(collection_renombramientos.find().sort('timestamp', -1))
    for doc in docs:
        doc['conteos'] = _conteos_renombramiento(doc)
    return docs


def _lista_unidades_form(con_categoria='asistencial'):
    filtro = {}
    if con_categoria == 'asistencial':
        filtro = {'activo': True, 'categoria': {'$ne': 'administrativa'}}
    elif con_categoria == 'administrativa':
        filtro = {'activo': True, 'categoria': 'administrativa'}
    else:
        filtro = {'activo': True}
    return list(collection_unidades.find(filtro).sort([('nombre', 1)]))


@unidades_bp.route('/tablero/unidades/renombramientos')
@login_required
def renombramientos_list():
    if current_user.rol != 'administrador':
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('home'))
    renombramientos = _renombramientos_con_conteos()
    return render_template('renombramientos.html', renombramientos=renombramientos)


@unidades_bp.route('/tablero/unidades/renombramientos/detectar', methods=['POST'])
@login_required
def renombramientos_detectar():
    if current_user.rol != 'administrador':
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('home'))
    resultado = detectar_renombramientos(
        collection_unidades, collection_eventos,
        collection_participantes, collection_usuarios, collection_renombramientos,
    )
    log_event(f"Usuario [{current_user.email}] ejecutó detección de renombramientos: "
              f"{resultado['total_huerfanos']} huérfano(s), {len(resultado['propuestas'])} propuesta(s).")
    flash(f"Detección completada: {resultado['total_huerfanos']} huérfano(s), "
          f"{len(resultado['propuestas'])} propuesta(s) guardadas.", 'success')
    renombramientos = _renombramientos_con_conteos()
    return render_template('renombramientos.html', renombramientos=renombramientos, detectar_result=resultado)


@unidades_bp.route('/tablero/unidades/renombramientos/crear', methods=['GET', 'POST'])
@login_required
def renombramiento_crear():
    if current_user.rol != 'administrador':
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('home'))

    unidades = _lista_unidades_form()

    if request.method == 'POST':
        nombre_anterior = request.form.get('nombre_anterior', '').strip()
        canonico = request.form.get('canonico', '').strip()
        region = request.form.get('region', '').strip() or None
        fecha_renombre = request.form.get('fecha_renombre', '').strip() or None

        doc = {
            'nombre_anterior': nombre_anterior,
            'canonico': canonico,
            'region': region,
            'fecha_renombre': fecha_renombre,
            'activo': True,
            'estado': 'pendiente',
            'creado_por': current_user.email,
            'timestamp': datetime.now(),
        }
        problemas = validar_colisiones(doc, collection_unidades)
        if problemas:
            for p in problemas:
                flash(p, 'error')
            return render_template('renombramiento_form.html', unidades=unidades, renombramiento=doc)

        collection_renombramientos.insert_one(doc)
        log_event(f"Usuario [{current_user.email}] creó el renombramiento "
                  f"'{nombre_anterior}' -> '{canonico}' ({region}).")
        flash(f'Renombramiento "{nombre_anterior}" -> "{canonico}" creado.', 'success')
        return redirect(url_for('unidades.renombramientos_list'))

    return render_template('renombramiento_form.html', unidades=unidades)


@unidades_bp.route('/tablero/unidades/renombramientos/<renombramiento_id>/editar', methods=['GET', 'POST'])
@login_required
def renombramiento_editar(renombramiento_id):
    if current_user.rol != 'administrador':
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('home'))

    renombramiento = collection_renombramientos.find_one({'_id': ObjectId(renombramiento_id)})
    if not renombramiento:
        flash('Renombramiento no encontrado.', 'error')
        return redirect(url_for('unidades.renombramientos_list'))

    unidades = _lista_unidades_form()

    if request.method == 'POST':
        nombre_anterior = request.form.get('nombre_anterior', '').strip()
        canonico = request.form.get('canonico', '').strip()
        region = request.form.get('region', '').strip() or None
        fecha_renombre = request.form.get('fecha_renombre', '').strip() or None

        doc = dict(renombramiento)
        doc.update({
            'nombre_anterior': nombre_anterior,
            'canonico': canonico,
            'region': region,
            'fecha_renombre': fecha_renombre,
        })
        problemas = validar_colisiones(doc, collection_unidades)
        if problemas:
            for p in problemas:
                flash(p, 'error')
            return render_template('renombramiento_form.html', unidades=unidades, renombramiento=doc)

        if renombramiento.get('estado') == 'aplicado':
            doc['estado'] = 'aplicado'

        # Aliases adicionales del canónico (textarea, uno por línea)
        aliases_extra = [a.strip() for a in request.form.get('nombres_anteriores', '').splitlines() if a.strip()]
        unidad_canonica = collection_unidades.find_one(
            {'nombre': canonico, 'region': region} if region else {'nombre': canonico}
        )
        if unidad_canonica:
            actuales = set(unidad_canonica.get('nombres_anteriores') or [])
            nuevos = sorted(set(aliases_extra) | actuales)
            collection_unidades.update_one(
                {'_id': unidad_canonica['_id']},
                {'$set': {'nombres_anteriores': nuevos, 'timestamp_updated': datetime.now()}}
            )
            invalidar_cache_unidades()

        collection_renombramientos.update_one(
            {'_id': ObjectId(renombramiento_id)},
            {'$set': {k: v for k, v in doc.items() if k != '_id' and k != 'conteos'}}
        )
        log_event(f"Usuario [{current_user.email}] editó el renombramiento "
                  f"'{nombre_anterior}' -> '{canonico}'.")
        flash('Renombramiento actualizado.', 'success')
        return redirect(url_for('unidades.renombramiento_detalle', renombramiento_id=renombramiento_id))

    unidad_canonica = collection_unidades.find_one(
        {'nombre': renombramiento.get('canonico'), 'region': renombramiento.get('region')}
        if renombramiento.get('region') else {'nombre': renombramiento.get('canonico')}
    )
    aliases_actuales = '\n'.join(unidad_canonica.get('nombres_anteriores') or []) if unidad_canonica else ''
    return render_template(
        'renombramiento_form.html', unidades=unidades,
        renombramiento=renombramiento, aliases_actuales=aliases_actuales,
    )


@unidades_bp.route('/tablero/unidades/renombramientos/<renombramiento_id>')
@login_required
def renombramiento_detalle(renombramiento_id):
    if current_user.rol != 'administrador':
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('home'))

    renombramiento = collection_renombramientos.find_one({'_id': ObjectId(renombramiento_id)})
    if not renombramiento:
        flash('Renombramiento no encontrado.', 'error')
        return redirect(url_for('unidades.renombramientos_list'))

    revision = revisar_renombramiento(
        renombramiento, collection_unidades, collection_eventos,
        collection_participantes, collection_usuarios,
    )
    return render_template(
        'renombramiento_detalle.html', renombramiento=renombramiento, revision=revision,
    )


@unidades_bp.route('/tablero/unidades/renombramientos/<renombramiento_id>/revisar', methods=['POST'])
@login_required
def renombramiento_revisar(renombramiento_id):
    if current_user.rol != 'administrador':
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('home'))

    renombramiento = collection_renombramientos.find_one({'_id': ObjectId(renombramiento_id)})
    if not renombramiento:
        flash('Renombramiento no encontrado.', 'error')
        return redirect(url_for('unidades.renombramientos_list'))

    revision = revisar_renombramiento(
        renombramiento, collection_unidades, collection_eventos,
        collection_participantes, collection_usuarios,
    )
    log_event(f"Usuario [{current_user.email}] revisó el renombramiento "
              f"'{renombramiento.get('nombre_anterior')}' -> '{renombramiento.get('canonico')}'.")
    return render_template(
        'renombramiento_detalle.html', renombramiento=renombramiento, revision=revision,
    )


@unidades_bp.route('/tablero/unidades/renombramientos/<renombramiento_id>/respaldo')
@login_required
def renombramiento_respaldo(renombramiento_id):
    if current_user.rol != 'administrador':
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('home'))

    renombramiento = collection_renombramientos.find_one({'_id': ObjectId(renombramiento_id)})
    if not renombramiento:
        flash('Renombramiento no encontrado.', 'error')
        return redirect(url_for('unidades.renombramientos_list'))

    respaldo = generar_respaldo(
        renombramiento, collection_unidades, collection_eventos,
        collection_participantes, collection_usuarios,
    )
    nombre_archivo = f"respaldo_renombramiento_{str(renombramiento['_id'])}.json"
    buffer = io.BytesIO(json.dumps(respaldo, ensure_ascii=False, indent=2).encode('utf-8'))
    return send_file(buffer, mimetype='application/json', as_attachment=True, download_name=nombre_archivo)


@unidades_bp.route('/tablero/unidades/renombramientos/<renombramiento_id>/aplicar', methods=['POST'])
@login_required
def renombramiento_aplicar(renombramiento_id):
    if current_user.rol != 'administrador':
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('home'))

    renombramiento = collection_renombramientos.find_one({'_id': ObjectId(renombramiento_id)})
    if not renombramiento:
        flash('Renombramiento no encontrado.', 'error')
        return redirect(url_for('unidades.renombramientos_list'))

    if renombramiento.get('estado') == 'aplicado':
        flash('Este renombramiento ya fue aplicado.', 'error')
        return redirect(url_for('unidades.renombramiento_detalle', renombramiento_id=renombramiento_id))

    if request.form.get('confirmo_respaldo') != 'on':
        flash('Debes descargar el respaldo y confirmar antes de aplicar.', 'error')
        return redirect(url_for('unidades.renombramiento_detalle', renombramiento_id=renombramiento_id))

    problemas = validar_colisiones(renombramiento, collection_unidades)
    if problemas:
        for p in problemas:
            flash(p, 'error')
        return redirect(url_for('unidades.renombramiento_detalle', renombramiento_id=renombramiento_id))

    conteo = aplicar_renombramiento(
        renombramiento, collection_unidades, collection_eventos,
        collection_participantes, collection_usuarios, collection_renombramientos,
        usuario_email=current_user.email,
    )
    invalidar_cache_unidades()
    log_event(f"Usuario [{current_user.email}] aplicó el renombramiento "
              f"'{renombramiento.get('nombre_anterior')}' -> '{renombramiento.get('canonico')}': {conteo}.")
    flash(f'Renombramiento aplicado: {conteo["eventos"]} eventos, '
          f'{conteo["participantes"]} participantes, {conteo["usuarios"]} usuarios.', 'success')
    return redirect(url_for('unidades.renombramiento_detalle', renombramiento_id=renombramiento_id))


@unidades_bp.route('/tablero/unidades/renombramientos/report')
@login_required
def renombramientos_report():
    if current_user.rol != 'administrador':
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('home'))
    resumen = resumen_huerfanos(
        collection_unidades, collection_eventos, collection_participantes, collection_usuarios,
    )
    return render_template('renombramientos_report.html', resumen=resumen)