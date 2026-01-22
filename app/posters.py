###
###
### Este archivo contiene funciones relacionadas con la gestión de pósters
### de concursos de investigación en CertiCSS.
###
###
from flask import Blueprint, request, render_template, redirect, url_for, flash, session, abort, send_from_directory, Response, current_app
from flask_login import login_required, current_user
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from PIL import Image
from functools import wraps
import os
import hashlib
import base64
from io import BytesIO

# Crear el blueprint para pósters
posters_bp = Blueprint('posters', __name__)

# Importar las colecciones de MongoDB desde el módulo principal
from app import (
    collection_eventos,
    collection_participantes, 
    collection_posters,
    collection_evaluaciones_poster
)
from app.logs import log_event

###
### Helper functions extracted from app.py
###

def get_poster_file_url(archivo_poster, codigo_evento):
    """Obtiene la URL correcta del archivo del póster, compatible con formatos antiguos y nuevos."""
    if not archivo_poster:
        return None
    
    # Formato nuevo (temporal): posters/{nanoid}_{filename}
    if archivo_poster.startswith('posters/'):
        return f"uploads/{archivo_poster}"
    
    # Formato original: {codigo_evento}_poster_{numero:02d}.pdf
    # Se guarda en: uploads/{codigo_evento}/posters/{codigo_evento}_poster_{numero:02d}.pdf
    if archivo_poster.startswith(f"{codigo_evento}_poster_"):
        return f"uploads/{codigo_evento}/posters/{archivo_poster}"
    
    # Formato con carpeta completa: {codigo_evento}/posters/{codigo_evento}_poster_{numero:02d}.pdf
    if archivo_poster.startswith(f"{codigo_evento}/"):
        return f"uploads/{archivo_poster}"
    
    # Si no coincide con ningún formato conocido, intentar formato original
    return f"uploads/{codigo_evento}/posters/{archivo_poster}"


def get_judge_session(codigo_evento, cedula_jurado):
    """
    Crea una sesión simulada para un jurado, permitiendo al administrador actuar en su nombre.
    """
    # Obtener datos del jurado
    jurado = collection_participantes.find_one({
        "codigo_evento": codigo_evento,
        "rol": "jurado_poster",
        "cedula": cedula_jurado
    })
    
    if not jurado:
        return None
        
    # Crear sesión simulada
    session['jurado_logged_in'] = True
    session['jurado_cedula'] = jurado['cedula']
    session['jurado_nombres'] = jurado['nombres']


# Import helper functions
from app.helpers import generate_nanoid, allowed_file
from app.auth import token_required
from app.usuarios import roles_required


###
### Registro de presentadores de póster
###
@posters_bp.route('/registrar_poster/<codigo_evento>', methods=['GET', 'POST'])
def registrar_poster(codigo_evento):
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    
    if evento is None:
        abort(404)
    
    # Verificar que el concurso de póster esté habilitado
    if not evento.get('concurso_poster', False):
        flash('El concurso de póster no está habilitado para este evento.', 'error')
        return redirect(url_for('home'))
    
    if evento.get('estado_evento') == 'cerrado':
        return render_template('registrar_poster.html',
            evento_cerrado=True,
            nombre_evento=evento['nombre'],
            afiche_url=url_for('static', filename='uploads/' + evento['afiche_750'].split('/')[-1])
        )
    
    if request.method == 'POST':
        nombres = request.form.get('nombres', '').strip()
        apellidos = request.form.get('apellidos', '').strip()
        cedula = request.form.get('cedula', '').strip()
        email = request.form.get('email', '').strip()
        telefono = request.form.get('telefono', '').strip()
        institucion = request.form.get('institucion', '').strip()
        # Obtener múltiples títulos de pósters
        titulos_posters = [t.strip() for t in request.form.getlist('titulo_poster[]') if t.strip()]
        # Obtener múltiples archivos de pósters
        archivos_posters = request.files.getlist('archivo_poster[]')
        passphrase = request.form.get('passphrase', '').strip()
        
        # Validaciones básicas
        if not all([nombres, apellidos, cedula, email, passphrase]):
            flash('Todos los campos obligatorios deben ser completados.', 'error')
            return render_template('registrar_poster.html', evento=evento)
        
        if not titulos_posters:
            flash('Debe registrar al menos un póster con título.', 'error')
            return render_template('registrar_poster.html', evento=evento)
        
        if len(archivos_posters) != len(titulos_posters):
            flash('Cada póster debe tener un título y un archivo asociado.', 'error')
            return render_template('registrar_poster.html', evento=evento)
        
        # Verificar si el participante ya existe
        participante_existente = collection_participantes.find_one({
            "cedula": cedula,
            "codigo_evento": codigo_evento,
            "rol": "presentador_poster"
        })
        
        # Si el participante no existe, crearlo
        if not participante_existente:
            # Generar nanoid para el participante
            nanoid_participante = generate_nanoid(cedula, codigo_evento, "presentador_poster")
            # Insertar en participantes
            participante_id = collection_participantes.insert_one({
                'nombres': nombres,
                'apellidos': apellidos,
                'cedula': cedula,
                'email': email,
                'telefono': telefono,
                'institucion': institucion,
                'rol': 'presentador_poster',
                'perfil': institucion,
                'region': '',
                'unidad': '',
                'codigo_evento': codigo_evento,
                'nanoid': nanoid_participante,
                'timestamp': datetime.now()
            }).inserted_id
        else:
            # Usar el ID del participante existente
            participante_id = participante_existente['_id']
        
        # Contar pósters existentes para generar número progresivo
        count_posters = collection_posters.count_documents({"codigo_evento": codigo_evento})
        
        # Procesar cada póster
        posters_registrados = 0
        for idx, (titulo_poster, archivo) in enumerate(zip(titulos_posters, archivos_posters)):
            # Validar que el archivo existe y es válido
            if not archivo or not archivo.filename:
                flash(f'El póster "{titulo_poster}" no tiene un archivo asociado.', 'error')
                continue
            
            if not allowed_file(archivo.filename):
                flash(f'El archivo del póster "{titulo_poster}" no tiene un formato válido.', 'error')
                continue
            
            # Generar nanoid único para cada póster
            nanoid = generate_nanoid(cedula, codigo_evento, f"{titulo_poster}_{idx}")
            numero_poster = count_posters + idx + 1
            
            # Preparar datos del póster
            poster_data = {
                'participante_id': participante_id,
                'nombres': nombres,
                'apellidos': apellidos,
                'cedula': cedula,
                'email': email,
                'telefono': telefono,
                'institucion': institucion,
                'titulo_poster': titulo_poster,
                'passphrase': generate_password_hash(passphrase),
                'codigo_evento': codigo_evento,
                'nanoid': nanoid,
                'numero_poster': numero_poster,
                'archivo_poster': None,
                'timestamp': datetime.now(),
                'estado': 'pendiente'  # pendiente, aprobado, rechazado
            }
            
            # Guardar el archivo con formato original: <codigo_evento>_poster_nn.pdf
            extension = os.path.splitext(archivo.filename)[1].lower()
            nombre_archivo = f"{codigo_evento}_poster_{numero_poster:02d}{extension}"
            carpeta_posters = os.path.join(current_app.config['UPLOAD_FOLDER'], codigo_evento, 'posters')
            os.makedirs(carpeta_posters, exist_ok=True)
            filepath = os.path.join(carpeta_posters, nombre_archivo)
            archivo.save(filepath)
            poster_data['archivo_poster'] = nombre_archivo
            
            # Insertar el póster
            collection_posters.insert_one(poster_data)
            posters_registrados += 1
        
        if posters_registrados > 0:
            if posters_registrados == 1:
                flash('¡Póster registrado exitosamente!', 'success')
            else:
                flash(f'¡{posters_registrados} pósters registrados exitosamente!', 'success')
            return redirect(url_for('posters.poster_login', codigo_evento=codigo_evento))
        else:
            flash('No se pudo registrar ningún póster. Por favor, verifique los archivos.', 'error')
            return render_template('registrar_poster.html', evento=evento)
    
    return render_template('registrar_poster.html', evento=evento)


###
### Login para presentadores de póster
###
@posters_bp.route('/concurso_login/<codigo_evento>', methods=['GET', 'POST'])
def poster_login(codigo_evento):
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    
    if evento is None:
        abort(404)
    
    # Verificar que el concurso de póster esté habilitado
    if not evento.get('concurso_poster', False):
        flash('El concurso de póster no está habilitado para este evento.', 'error')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        cedula = request.form.get('cedula', '').strip()
        passphrase = request.form.get('passphrase', '').strip()
        
        poster = collection_posters.find_one({
            "cedula": cedula,
            "codigo_evento": codigo_evento
        })
        
        if poster and check_password_hash(poster['passphrase'], passphrase):
            session['poster_user'] = {
                'cedula': cedula,
                'codigo_evento': codigo_evento,
                'nanoid': poster['nanoid']
            }
            return redirect(url_for('posters.editar_poster', codigo_evento=codigo_evento))
        else:
            flash('Cédula o passphrase incorrectos.', 'error')
    
    return render_template('poster_login.html', evento=evento)


###
### Cerrar sesión de póster/jurado
###
@posters_bp.route('/concurso_logout/<codigo_evento>')
def poster_logout(codigo_evento):
    # Verificar si es un administrador suplantando ANTES de borrar la sesión
    is_admin_impersonating = session.get('admin_impersonating', False)
    
    # Limpiar todas las variables de sesión relacionadas con jurados
    session.pop('poster_user', None)
    session.pop('jurado_user', None)
    session.pop('jurado_logged_in', None)
    session.pop('jurado_cedula', None)
    session.pop('jurado_nombres', None)
    session.pop('jurado_apellidos', None)
    session.pop('jurado_email', None)
    session.pop('admin_impersonating', None)
    
    # Redirigir a la página de administración de pósters si venimos de ahí
    if is_admin_impersonating:
        return redirect(url_for('posters.admin_posters', codigo_evento=codigo_evento))
        
    # Si no, redirigir a la página de información del concurso
    return redirect(url_for('posters.info_concurso_poster', codigo_evento=codigo_evento))


###
### Editar póster
###
@posters_bp.route('/editar_poster/<codigo_evento>', methods=['GET', 'POST'])
def editar_poster(codigo_evento):
    if 'poster_user' not in session or session['poster_user']['codigo_evento'] != codigo_evento:
        return redirect(url_for('posters.poster_login', codigo_evento=codigo_evento))
    
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    cedula = session['poster_user']['cedula']
    
    # Obtener todos los pósters del participante
    todos_posters = list(collection_posters.find({
        "cedula": cedula,
        "codigo_evento": codigo_evento
    }).sort("numero_poster", 1))
    
    if not todos_posters:
        flash('Póster no encontrado.', 'error')
        return redirect(url_for('posters.poster_login', codigo_evento=codigo_evento))
    
    # Póster por defecto (el primero)
    poster = todos_posters[0]
    
    if request.method == 'POST':
        action = request.form.get('action', 'editar')
        
        # Si es para añadir un nuevo póster
        if action == 'añadir_poster':
            # Obtener datos del formulario
            titulo_poster = request.form.get('nuevo_titulo_poster', '').strip()
            poster_file = request.files.get('nuevo_poster_file')
            
            if not titulo_poster:
                flash('El título del póster es obligatorio.', 'error')
                return render_template('editar_poster.html', evento=evento, poster=poster, todos_posters=todos_posters)
            
            if not poster_file or not poster_file.filename:
                flash('Debe subir un archivo para el nuevo póster.', 'error')
                return render_template('editar_poster.html', evento=evento, poster=poster, todos_posters=todos_posters)
            
            # Verificar tipo de archivo
            if not allowed_file(poster_file.filename):
                flash('Solo se permiten archivos PDF, JPG, JPEG o PNG.', 'error')
                return render_template('editar_poster.html', evento=evento, poster=poster, todos_posters=todos_posters)
            
            # Obtener datos del participante del primer póster
            datos_participante = todos_posters[0]
            participante = collection_participantes.find_one({
                "cedula": cedula,
                "codigo_evento": codigo_evento,
                "rol": "presentador_poster"
            })
            
            if not participante:
                flash('Participante no encontrado.', 'error')
                return render_template('editar_poster.html', evento=evento, poster=poster, todos_posters=todos_posters)
            
            # Contar pósters existentes para generar número progresivo
            count_posters = collection_posters.count_documents({"codigo_evento": codigo_evento})
            numero_poster = count_posters + 1
            
            # Generar nanoid único para el nuevo póster
            nanoid = generate_nanoid(cedula, codigo_evento, f"{titulo_poster}_{len(todos_posters)}")
            
            # Guardar el archivo con formato original: <codigo_evento>_poster_nn.pdf
            extension = os.path.splitext(poster_file.filename)[1].lower()
            nombre_archivo = f"{codigo_evento}_poster_{numero_poster:02d}{extension}"
            carpeta_posters = os.path.join(current_app.config['UPLOAD_FOLDER'], codigo_evento, 'posters')
            os.makedirs(carpeta_posters, exist_ok=True)
            ruta_archivo = os.path.join(carpeta_posters, nombre_archivo)
            
            # Guardar archivo
            poster_file.save(ruta_archivo)
            
            # Obtener la passphrase del póster existente
            passphrase_hash = todos_posters[0].get('passphrase')
            
            # Preparar datos del nuevo póster
            nuevo_poster_data = {
                'participante_id': participante['_id'],
                'nombres': datos_participante['nombres'],
                'apellidos': datos_participante['apellidos'],
                'cedula': cedula,
                'email': datos_participante['email'],
                'telefono': datos_participante.get('telefono', ''),
                'institucion': datos_participante.get('institucion', ''),
                'titulo_poster': titulo_poster,
                'passphrase': passphrase_hash,
                'codigo_evento': codigo_evento,
                'nanoid': nanoid,
                'numero_poster': numero_poster,
                'archivo_poster': nombre_archivo,
                'timestamp': datetime.now(),
                'estado': 'pendiente'
            }
            
            # Insertar el nuevo póster
            collection_posters.insert_one(nuevo_poster_data)
            
            flash('¡Nuevo póster añadido exitosamente!', 'success')
            
            # Recargar todos los pósters
            todos_posters = list(collection_posters.find({
                "cedula": cedula,
                "codigo_evento": codigo_evento
            }).sort("numero_poster", 1))
            
            # Seleccionar el nuevo póster como el actual
            poster = next((p for p in todos_posters if p['nanoid'] == nanoid), todos_posters[-1])
        
        else:
            # Editar póster existente
            # Obtener el nanoid del póster a editar desde el formulario
            nanoid_editar = request.form.get('nanoid_poster', poster['nanoid'])
            poster_editar = next((p for p in todos_posters if p['nanoid'] == nanoid_editar), None)
            
            if not poster_editar:
                flash('Póster no encontrado.', 'error')
                return render_template('editar_poster.html', evento=evento, poster=poster, todos_posters=todos_posters)
            
            # Actualizar datos básicos
            nombres = request.form.get('nombres', '').strip()
            apellidos = request.form.get('apellidos', '').strip()
            email = request.form.get('email', '').strip()
            telefono = request.form.get('telefono', '').strip()
            institucion = request.form.get('institucion', '').strip()
            titulo_poster = request.form.get('titulo_poster', '').strip()
            
            update_data = {
                'nombres': nombres,
                'apellidos': apellidos,
                'email': email,
                'telefono': telefono,
                'institucion': institucion,
                'titulo_poster': titulo_poster
            }
            
            # Manejar subida de archivo (PDF, JPG, PNG)
            poster_file = request.files.get('poster_file')
            if poster_file and poster_file.filename:
                # Verificar tipo de archivo
                if not allowed_file(poster_file.filename):
                    flash('Solo se permiten archivos PDF, JPG, JPEG o PNG.', 'error')
                    return render_template('editar_poster.html', evento=evento, poster=poster_editar, todos_posters=todos_posters)
                
                # Guardar el archivo con formato original: <codigo_evento>_poster_nn.pdf
                extension = os.path.splitext(poster_file.filename)[1].lower()
                nombre_archivo = f"{codigo_evento}_poster_{poster_editar['numero_poster']:02d}{extension}"
                carpeta_posters = os.path.join(current_app.config['UPLOAD_FOLDER'], codigo_evento, 'posters')
                os.makedirs(carpeta_posters, exist_ok=True)
                ruta_archivo = os.path.join(carpeta_posters, nombre_archivo)
                
                # Guardar archivo
                poster_file.save(ruta_archivo)
                update_data['archivo_poster'] = nombre_archivo
                
                flash('Póster actualizado exitosamente.', 'success')
            
            # Actualizar el póster específico en base de datos
            collection_posters.update_one(
                {"nanoid": nanoid_editar},
                {"$set": update_data}
            )
            
            # Actualizar también en participantes
            participante = collection_participantes.find_one({
                "cedula": cedula,
                "codigo_evento": codigo_evento,
                "rol": "presentador_poster"
            })
            if participante:
                collection_participantes.update_one(
                    {"_id": participante['_id']},
                    {"$set": {
                        'nombres': nombres,
                        'apellidos': apellidos,
                        'email': email,
                        'telefono': telefono,
                        'institucion': institucion,
                        'perfil': institucion
                    }}
                )
            
            # Recargar todos los pósters
            todos_posters = list(collection_posters.find({
                "cedula": cedula,
                "codigo_evento": codigo_evento
            }).sort("numero_poster", 1))
            
            # Actualizar el póster actual
            poster = next((p for p in todos_posters if p['nanoid'] == nanoid_editar), todos_posters[0])
    
    return render_template('editar_poster.html', evento=evento, poster=poster, todos_posters=todos_posters)


###
### Registro de jurados
###
@posters_bp.route('/registrar_jurado/<codigo_evento>', methods=['GET', 'POST'])
def registrar_jurado(codigo_evento):
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    
    if evento is None:
        abort(404)
    
    # Verificar que el concurso de póster esté habilitado
    if not evento.get('concurso_poster', False):
        flash('El concurso de póster no está habilitado para este evento.', 'error')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        nombres = request.form.get('nombres', '').strip()
        apellidos = request.form.get('apellidos', '').strip()
        cedula = request.form.get('cedula', '').strip()
        email = request.form.get('email', '').strip()
        institucion = request.form.get('institucion', '').strip()
        especialidad = request.form.get('especialidad', '').strip()
        passphrase = request.form.get('passphrase', '').strip()
        
        # Validaciones básicas
        if not all([nombres, apellidos, cedula, email, especialidad, passphrase]):
            flash('Todos los campos son obligatorios.', 'error')
            return render_template('registrar_jurado.html', evento=evento)
        
        # Verificar si ya existe un jurado con la misma cédula y evento
        jurado_existente = collection_participantes.find_one({
            "cedula": cedula,
            "codigo_evento": codigo_evento,
            "rol": "jurado_poster"
        })
        
        if jurado_existente:
            flash('Ya existe un registro de jurado para esta cédula en este evento.', 'error')
            return render_template('registrar_jurado.html', evento=evento)
        
        # Generar nanoid
        nanoid = generate_nanoid(cedula, codigo_evento, "jurado")
        
        # Insertar en participantes con rol de jurado
        collection_participantes.insert_one({
            'nombres': nombres,
            'apellidos': apellidos,
            'cedula': cedula,
            'email': email,
            'institucion': institucion,
            'especialidad': especialidad,
            'passphrase': generate_password_hash(passphrase),
            'rol': 'jurado_poster',
            'perfil': especialidad,
            'region': '',
            'unidad': '',
            'codigo_evento': codigo_evento,
            'nanoid': nanoid,
            'timestamp': datetime.now(),
            'indice_registro': datetime.now().strftime('%Y%m%d'),
            'tipo_evento': evento.get('modalidad', 'Virtual')
        })
        
        flash('Registro de jurado exitoso. Guarde su passphrase para acceder a las evaluaciones.', 'success')
        return redirect(url_for('posters.registrar_jurado', codigo_evento=codigo_evento))
    
    return render_template('registrar_jurado.html', evento=evento)


###
### Login para jurados
###
@posters_bp.route('/jurado_login/<codigo_evento>', methods=['GET', 'POST'])
def jurado_login(codigo_evento):
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    
    if evento is None:
        abort(404)
    
    # Verificar que el concurso de póster esté habilitado
    if not evento.get('concurso_poster', False):
        flash('El concurso de póster no está habilitado para este evento.', 'error')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        cedula = request.form.get('cedula', '').strip()
        passphrase = request.form.get('passphrase', '').strip()
        
        jurado = collection_participantes.find_one({
            "cedula": cedula,
            "codigo_evento": codigo_evento,
            "rol": "jurado_poster"
        })
        
        if jurado and check_password_hash(jurado['passphrase'], passphrase):
            session['jurado_user'] = {
                'cedula': cedula,
                'codigo_evento': codigo_evento,
                'nanoid': jurado['nanoid']
            }
            return redirect(url_for('posters.evaluar_posters', codigo_evento=codigo_evento))
        else:
            flash('Cédula o passphrase incorrectos.', 'error')
    
    return render_template('jurado_login.html', evento=evento)


###
### Panel de evaluación de pósters
###
@posters_bp.route('/evaluar_posters/<codigo_evento>')
def evaluar_posters(codigo_evento):
    # Verificar si hay una sesión de jurado activa, una sesión de jurado antigua o si es un administrador suplantando
    jurado_logged_in = (
        session.get('jurado_logged_in') or 
        (session.get('jurado_user') and session['jurado_user'].get('codigo_evento') == codigo_evento) or
        session.get('admin_impersonating')
    )
    
    if not jurado_logged_in:
        return redirect(url_for('posters.jurado_login', codigo_evento=codigo_evento))
    
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)
        
    posters = list(collection_posters.find({"codigo_evento": codigo_evento}).sort("numero_poster"))
    
    # Agregar URL de archivo a cada póster
    for poster in posters:
        poster['archivo_url'] = get_poster_file_url(poster.get('archivo_poster'), codigo_evento)
    
    # Obtener evaluaciones existentes del jurado
    evaluaciones_existentes = {}
    cedula_jurado = None
    
    # Determinar la cédula del jurado según el tipo de sesión
    if session.get('jurado_user'):
        cedula_jurado = session['jurado_user'].get('cedula')
    elif session.get('jurado_cedula'):
        cedula_jurado = session['jurado_cedula']
    
    # Si hay una cédula de jurado, buscar sus evaluaciones
    if cedula_jurado:
        evaluaciones = collection_evaluaciones_poster.find({
            "codigo_evento": codigo_evento,
            "cedula_jurado": cedula_jurado
        })
        
        for eval in evaluaciones:
            evaluaciones_existentes[eval['nanoid_poster']] = eval
    
    return render_template('evaluar_posters.html', 
                         evento=evento, 
                         posters=posters, 
                         evaluaciones_existentes=evaluaciones_existentes)


###
### Formulario de evaluación individual
###
@posters_bp.route('/evaluar_poster/<codigo_evento>/<nanoid_poster>', methods=['GET', 'POST'])
def evaluar_poster(codigo_evento, nanoid_poster):
    # Verificar si hay una sesión de jurado activa, una sesión de jurado antigua o si es un administrador suplantando
    jurado_logged_in = (
        session.get('jurado_logged_in') or 
        (session.get('jurado_user') and session['jurado_user'].get('codigo_evento') == codigo_evento) or
        session.get('admin_impersonating')
    )
    
    if not jurado_logged_in:
        return redirect(url_for('posters.jurado_login', codigo_evento=codigo_evento))
    
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)
        
    poster = collection_posters.find_one({"nanoid": nanoid_poster})
    if not poster:
        abort(404)
    
    # Agregar URL de archivo al póster
    poster['archivo_url'] = get_poster_file_url(poster.get('archivo_poster'), codigo_evento)
    
    # Determinar la cédula del jurado según el tipo de sesión
    cedula_jurado = None
    if session.get('jurado_user'):
        cedula_jurado = session['jurado_user'].get('cedula')
    elif session.get('jurado_cedula'):
        cedula_jurado = session['jurado_cedula']
    
    # Verificar evaluación existente
    evaluacion_existente = None
    if cedula_jurado:  # Solo buscar evaluación si tenemos una cédula de jurado
        evaluacion_existente = collection_evaluaciones_poster.find_one({
            "codigo_evento": codigo_evento,
            "nanoid_poster": nanoid_poster,
            "cedula_jurado": cedula_jurado
        })
    
    if request.method == 'POST':
        if not cedula_jurado:
            flash('No se pudo identificar al jurado. Por favor, inicie sesión nuevamente.', 'error')
            return redirect(url_for('posters.jurado_login', codigo_evento=codigo_evento))
            
        # Recoger puntuaciones
        introduccion_objetivos = int(request.form.get('introduccion_objetivos', 0))
        metodologia = int(request.form.get('metodologia', 0))
        resultados = int(request.form.get('resultados', 0))
        conclusiones = int(request.form.get('conclusiones', 0))
        diseno_organizacion = int(request.form.get('diseno_organizacion', 0))
        imagenes_graficos = int(request.form.get('imagenes_graficos', 0))
        claridad_comunicacion = int(request.form.get('claridad_comunicacion', 0))
        dominio_tema = int(request.form.get('dominio_tema', 0))
        comentarios = request.form.get('comentarios', '').strip()
        
        # Obtener nombres del jurado según el tipo de sesión
        nombres_jurado = session.get('jurado_nombres') or (session.get('jurado_user', {}).get('nombres') or '')
        apellidos_jurado = session.get('jurado_apellidos') or (session.get('jurado_user', {}).get('apellidos') or '')
        email_jurado = session.get('jurado_email') or (session.get('jurado_user', {}).get('email') or '')
        
        # Calcular puntuaciones
        contenido_score = (introduccion_objetivos + metodologia + resultados + conclusiones) / 4.0
        presentacion_visual_score = (diseno_organizacion + imagenes_graficos) / 2.0
        presentacion_oral_score = (claridad_comunicacion + dominio_tema) / 2.0
        puntuacion_final = (contenido_score + presentacion_visual_score + presentacion_oral_score) / 3.0
        
        # Crear o actualizar evaluación
        evaluacion_data = {
            'codigo_evento': codigo_evento,
            'nanoid_poster': nanoid_poster,
            'cedula_jurado': cedula_jurado,
            'nombres_jurado': nombres_jurado,
            'apellidos_jurado': apellidos_jurado,
            'email_jurado': email_jurado,
            'introduccion_objetivos': introduccion_objetivos,
            'metodologia': metodologia,
            'resultados': resultados,
            'conclusiones': conclusiones,
            'diseno_organizacion': diseno_organizacion,
            'imagenes_graficos': imagenes_graficos,
            'claridad_comunicacion': claridad_comunicacion,
            'dominio_tema': dominio_tema,
            'contenido_score': contenido_score,
            'presentacion_visual_score': presentacion_visual_score,
            'presentacion_oral_score': presentacion_oral_score,
            'puntuacion_final': puntuacion_final,
            'comentarios': comentarios,
            'timestamp': datetime.now()
        }
        
        if evaluacion_existente:
            # Actualizar evaluación existente
            collection_evaluaciones_poster.update_one(
                {"_id": evaluacion_existente["_id"]},
                {"$set": evaluacion_data}
            )
            flash('Evaluación actualizada exitosamente.', 'success')
        else:
            # Crear nueva evaluación
            collection_evaluaciones_poster.insert_one(evaluacion_data)
            flash('Evaluación guardada exitosamente.', 'success')
        
        return redirect(url_for('posters.evaluar_posters', codigo_evento=codigo_evento))
    
    return render_template('evaluar_poster.html', 
                         evento=evento, 
                         poster=poster, 
                         evaluacion=evaluacion_existente)


###
### Ver calificaciones (para presentadores)
###
@posters_bp.route('/ver_calificaciones/<codigo_evento>')
def ver_calificaciones(codigo_evento):
    if 'poster_user' not in session or session['poster_user']['codigo_evento'] != codigo_evento:
        return redirect(url_for('posters.poster_login', codigo_evento=codigo_evento))
    
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    posters = list(collection_posters.find({
        "cedula": session['poster_user']['cedula'],
        "codigo_evento": codigo_evento
    }).sort("numero_poster", 1))
    
    if not posters:
        abort(404)
    
    selected_nanoid = request.args.get('nanoid')
    poster = next((p for p in posters if p['nanoid'] == selected_nanoid), None)
    if not poster:
        poster = posters[0]
    
    # Obtener todas las evaluaciones del póster
    evaluaciones = list(collection_evaluaciones_poster.find({
        "codigo_evento": codigo_evento,
        "nanoid_poster": poster['nanoid']
    }))
    
    # Obtener datos de jurados
    jurados_data = {}
    for eval in evaluaciones:
        jurado = collection_participantes.find_one({
            "cedula": eval['cedula_jurado'],
            "codigo_evento": codigo_evento,
            "rol": "jurado_poster"
        })
        if jurado:
            jurados_data[eval['cedula_jurado']] = f"{jurado['nombres']} {jurado['apellidos']}"
    
    # Calcular promedio final
    promedio_final = 0
    if evaluaciones:
        promedio_final = sum(eval['puntuacion_final'] for eval in evaluaciones) / len(evaluaciones)
    
    return render_template('ver_calificaciones.html', 
                         evento=evento, 
                         posters=posters,
                         poster=poster, 
                         evaluaciones=evaluaciones,
                         jurados_data=jurados_data,
                         promedio_final=promedio_final)


###
### Información del concurso de póster
###
@posters_bp.route('/concurso_poster/<codigo_evento>')
def info_concurso_poster(codigo_evento):
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)
    
    # Verificar que el concurso de póster esté habilitado
    if not evento.get('concurso_poster', False):
        flash('El concurso de póster no está habilitado para este evento.', 'error')
        return redirect(url_for('home'))
    
    # Contar pósters registrados
    total_posters = collection_posters.count_documents({"codigo_evento": codigo_evento})
    
    # Contar jurados registrados
    total_jurados = collection_participantes.count_documents({
        "codigo_evento": codigo_evento,
        "rol": "jurado_poster"
    })
    
    return render_template('info_concurso_poster.html', 
                         evento=evento, 
                         total_posters=total_posters,
                         total_jurados=total_jurados)


###
### Vista pública de posters
###
@posters_bp.route('/concurso_investigacion/<codigo_evento>', methods=['GET'])
@token_required
def concurso_investigacion_publico(codigo_evento):
    # Obtener el evento
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)
    
    # Verificar que el concurso de póster esté habilitado
    if not evento.get('concurso_poster', False):
        abort(404)
    
    # Obtener los posters del evento
    posters = list(collection_posters.find({"codigo_evento": codigo_evento}).sort("timestamp", -1))
    
    # Agregar URL de archivo a cada póster
    for poster in posters:
        poster['archivo_url'] = get_poster_file_url(poster.get('archivo_poster'), codigo_evento)
    
    return render_template('concurso_publico.html', evento=evento, posters=posters)


###
### Resultados públicos del concurso
###
@posters_bp.route('/concurso/<codigo_evento>')
def resultados_concurso_publico(codigo_evento):
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)
    
    # Verificar que el concurso de póster esté habilitado
    if not evento.get('concurso_poster', False):
        abort(404)
    
    # Obtener pósters con sus promedios
    posters = list(collection_posters.find({"codigo_evento": codigo_evento}))
    
    resultados = []
    for poster in posters:
        evaluaciones = list(collection_evaluaciones_poster.find({
            "codigo_evento": codigo_evento,
            "nanoid_poster": poster['nanoid']
        }))
        
        if evaluaciones:
            promedio = sum(e['puntuacion_final'] for e in evaluaciones) / len(evaluaciones)
            # Crear una copia del poster sin información sensible
            poster_publico = {
                'nombres': poster['nombres'],
                'apellidos': poster['apellidos'],
                'institucion': poster.get('institucion', ''),
                'titulo_poster': poster['titulo_poster'],
                'numero_poster': poster['numero_poster'],
                'archivo_poster': poster.get('archivo_poster'),
                'nanoid': poster['nanoid']
            }
            resultados.append({
                'poster': poster_publico,
                'promedio': promedio,
                'num_evaluaciones': len(evaluaciones)
            })
    
    # Ordenar por promedio descendente
    resultados.sort(key=lambda x: x['promedio'], reverse=True)
    
    return render_template('resultados_concurso_publico.html', 
                         evento=evento, 
                         resultados=resultados)


###
### Admin Routes - Poster Management
###

@posters_bp.route('/tablero/posters/<codigo_evento>/login_como_jurado/<cedula_jurado>')
@login_required
def login_as_judge(codigo_evento, cedula_jurado):
    """
    Permite al administrador iniciar sesión como un jurado específico para editar evaluaciones.
    """
    # Verificar que el usuario sea administrador
    if not current_user.is_authenticated or current_user.rol != 'administrador':
        abort(403)
    
    # Obtener datos del evento
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)
    
    # Obtener datos del jurado
    jurado = collection_participantes.find_one({
        "codigo_evento": codigo_evento,
        "rol": "jurado_poster",
        "cedula": cedula_jurado
    })
    
    if not jurado:
        flash('No se encontró al jurado especificado.', 'error')
        return redirect(url_for('posters.admin_posters', codigo_evento=codigo_evento))
    
    # Configurar la sesión del jurado
    get_judge_session(codigo_evento, cedula_jurado)
    
    # Marcar que es un administrador suplantando
    session['admin_impersonating'] = True
    
    flash(f'Has iniciado sesión como {jurado["nombres"]} {jurado["apellidos"]} (Jurado).', 'info')
    return redirect(url_for('posters.evaluar_posters', codigo_evento=codigo_evento))


@posters_bp.route('/tablero/posters/<codigo_evento>')
@login_required
def admin_posters(codigo_evento):
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)
    
    # Verificar que el concurso de póster esté habilitado
    if not evento.get('concurso_poster', False):
        flash('El concurso de póster no está habilitado para este evento.', 'error')
        return redirect(url_for('listar_participantes', codigo_evento=codigo_evento))
    
    # Obtener todos los pósters ordenados por número
    posters = list(collection_posters.find(
        {"codigo_evento": codigo_evento}
    ).sort("numero_poster", 1))
    
    # Agregar URL de archivo a cada póster para compatibilidad
    for poster in posters:
        poster['archivo_url'] = get_poster_file_url(poster.get('archivo_poster'), codigo_evento)
    
    # Obtener todos los jurados
    jurados = list(collection_participantes.find({
        "codigo_evento": codigo_evento,
        "rol": "jurado_poster"
    }).sort([("apellidos", 1), ("nombres", 1)]))
    
    # Obtener todas las evaluaciones
    evaluaciones = list(collection_evaluaciones_poster.find({
        "codigo_evento": codigo_evento
    }))
    
    # Agrupar evaluaciones por póster
    evaluaciones_por_poster = {}
    for eval in evaluaciones:
        nanoid = eval['nanoid_poster']
        if nanoid not in evaluaciones_por_poster:
            evaluaciones_por_poster[nanoid] = []
        evaluaciones_por_poster[nanoid].append(eval)
    
    # Calcular promedios por póster
    promedios_poster = {}
    for poster in posters:
        nanoid = poster['nanoid']
        if nanoid in evaluaciones_por_poster:
            evaluaciones_poster = evaluaciones_por_poster[nanoid]
            if evaluaciones_poster:
                promedio = sum(e['puntuacion_final'] for e in evaluaciones_poster) / len(evaluaciones_poster)
                promedios_poster[nanoid] = promedio
    
    # Verificar si hay una sesión de jurado activa
    jurado_activo = None
    if 'jurado_logged_in' in session and session.get('codigo_evento') == codigo_evento:
        jurado_activo = {
            'cedula': session.get('jurado_cedula'),
            'nombres': session.get('jurado_nombres'),
            'apellidos': session.get('jurado_apellidos')
        }
    
    return render_template('admin_posters.html', 
                         evento=evento,
                         posters=posters,
                         jurados=jurados,
                         evaluaciones_por_poster=evaluaciones_por_poster,
                         promedios_poster=promedios_poster,
                         jurado_activo=jurado_activo)


@posters_bp.route('/tablero/posters/<codigo_evento>/resultados')
@login_required
def resultados_poster(codigo_evento):
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)
    
    # Verificar que el concurso de póster esté habilitado
    if not evento.get('concurso_poster', False):
        flash('El concurso de póster no está habilitado para este evento.', 'error')
        return redirect(url_for('listar_participantes', codigo_evento=codigo_evento))
    
    # Obtener pósters con sus promedios
    posters = list(collection_posters.find({"codigo_evento": codigo_evento}))
    
    resultados = []
    for poster in posters:
        evaluaciones = list(collection_evaluaciones_poster.find({
            "codigo_evento": codigo_evento,
            "nanoid_poster": poster['nanoid']
        }))
        
        if evaluaciones:
            promedio = sum(e['puntuacion_final'] for e in evaluaciones) / len(evaluaciones)
            resultados.append({
                'poster': poster,
                'promedio': promedio,
                'num_evaluaciones': len(evaluaciones)
            })
    
    # Ordenar por promedio descendente
    resultados.sort(key=lambda x: x['promedio'], reverse=True)
    
    # Obtener todos los jurados (para la vista detallada)
    jurados = list(collection_participantes.find({
        "codigo_evento": codigo_evento,
        "rol": "jurado_poster"
    }).sort([("apellidos", 1), ("nombres", 1)]))
    
    # Obtener todas las evaluaciones (para la vista detallada)
    all_evaluaciones = list(collection_evaluaciones_poster.find({
        "codigo_evento": codigo_evento
    }))
    
    # Agrupar evaluaciones por póster
    evaluaciones_por_poster = {}
    for eval in all_evaluaciones:
        nanoid = eval['nanoid_poster']
        if nanoid not in evaluaciones_por_poster:
            evaluaciones_por_poster[nanoid] = []
        evaluaciones_por_poster[nanoid].append(eval)
        
    # Diccionario de promedios para acceso rápido
    promedios_poster = {r['poster']['nanoid']: r['promedio'] for r in resultados}
    
    return render_template('resultados_poster.html', 
                         evento=evento, 
                         resultados=resultados,
                         posters=posters,
                         jurados=jurados,
                         evaluaciones_por_poster=evaluaciones_por_poster,
                         promedios_poster=promedios_poster)


@posters_bp.route('/tablero/eliminar_jurado/<codigo_evento>/<cedula_jurado>', methods=['POST'])
@login_required
def eliminar_jurado_poster(codigo_evento, cedula_jurado):
    # Verificar permisos (solo administradores o coordinadores)
    if current_user.rol not in ['administrador', 'denadoi']:
        flash('No tienes permisos para realizar esta acción.', 'error')
        return redirect(url_for('posters.admin_posters', codigo_evento=codigo_evento))
    
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)
    
    # Verificar que el concurso de póster esté habilitado
    if not evento.get('concurso_poster', False):
        flash('El concurso de póster no está habilitado para este evento.', 'error')
        return redirect(url_for('posters.admin_posters', codigo_evento=codigo_evento))
    
    # Obtener información del jurado antes de eliminarlo
    jurado = collection_participantes.find_one({
        "codigo_evento": codigo_evento,
        "cedula": cedula_jurado,
        "rol": "jurado_poster"
    })
    
    if not jurado:
        flash('Jurado no encontrado.', 'error')
        return redirect(url_for('posters.admin_posters', codigo_evento=codigo_evento))
    
    try:
        # Eliminar todas las evaluaciones del jurado
        result_evaluaciones = collection_evaluaciones_poster.delete_many({
            "codigo_evento": codigo_evento,
            "cedula_jurado": cedula_jurado
        })
        
        # Eliminar el jurado de la colección de participantes
        result_jurado = collection_participantes.delete_one({
            "codigo_evento": codigo_evento,
            "cedula": cedula_jurado,
            "rol": "jurado_poster"
        })
        
        if result_jurado.deleted_count > 0:
            log_event(f"Usuario [{current_user.email}] eliminó al jurado {jurado['nombres']} {jurado['apellidos']} (cédula: {cedula_jurado}) del evento {codigo_evento}. Se eliminaron {result_evaluaciones.deleted_count} evaluaciones.")
            flash(f'Jurado {jurado["nombres"]} {jurado["apellidos"]} eliminado exitosamente. Se eliminaron {result_evaluaciones.deleted_count} evaluaciones.', 'success')
        else:
            flash('Error al eliminar el jurado.', 'error')
            
    except Exception as e:
        flash(f'Error al eliminar el jurado: {str(e)}', 'error')
        log_event(f"Error al eliminar jurado {cedula_jurado} del evento {codigo_evento}: {str(e)}")
    
    return redirect(url_for('posters.admin_posters', codigo_evento=codigo_evento))


@posters_bp.route('/tablero/editar_poster_admin/<codigo_evento>/<nanoid_poster>', methods=['GET', 'POST'])
@login_required
def editar_poster_admin(codigo_evento, nanoid_poster):
    # Verificar permisos (solo administradores o coordinadores)
    if current_user.rol not in ['administrador', 'denadoi']:
        flash('No tienes permisos para realizar esta acción.', 'error')
        return redirect(url_for('posters.admin_posters', codigo_evento=codigo_evento))
    
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)
    
    # Verificar que el concurso de póster esté habilitado
    if not evento.get('concurso_poster', False):
        flash('El concurso de póster no está habilitado para este evento.', 'error')
        return redirect(url_for('posters.admin_posters', codigo_evento=codigo_evento))
    
    poster = collection_posters.find_one({
        "nanoid": nanoid_poster,
        "codigo_evento": codigo_evento
    })
    
    if not poster:
        flash('Póster no encontrado.', 'error')
        return redirect(url_for('posters.admin_posters', codigo_evento=codigo_evento))
    
    # Agregar URL de archivo al póster
    poster['archivo_url'] = get_poster_file_url(poster.get('archivo_poster'), codigo_evento)
    
    if request.method == 'POST':
        # Actualizar datos básicos
        nombres = request.form.get('nombres', '').strip()
        apellidos = request.form.get('apellidos', '').strip()
        email = request.form.get('email', '').strip()
        telefono = request.form.get('telefono', '').strip()
        institucion = request.form.get('institucion', '').strip()
        titulo_poster = request.form.get('titulo_poster', '').strip()
        nueva_passphrase = request.form.get('nueva_passphrase', '').strip()
        
        # Validar campos requeridos
        if not all([nombres, apellidos, titulo_poster]):
            flash('Los campos nombres, apellidos y título son obligatorios.', 'error')
            return render_template('editar_poster_admin.html', evento=evento, poster=poster)
        
        update_data = {
            'nombres': nombres,
            'apellidos': apellidos,
            'email': email,
            'telefono': telefono,
            'institucion': institucion,
            'titulo_poster': titulo_poster
        }
        
        # Actualizar passphrase si se proporciona una nueva
        if nueva_passphrase:
            update_data['passphrase'] = generate_password_hash(nueva_passphrase)
        
        # Manejar subida de archivo PDF (opcional)
        poster_file = request.files.get('poster_file')
        if poster_file and poster_file.filename:
            if poster_file.filename.endswith('.pdf'):
                # Crear carpeta del evento si no existe
                carpeta_posters = os.path.join(current_app.config['UPLOAD_FOLDER'], codigo_evento, 'posters')
                os.makedirs(carpeta_posters, exist_ok=True)
                
                # Nombre del archivo
                nombre_archivo = f"{codigo_evento}_poster_{poster['numero_poster']:02d}.pdf"
                ruta_archivo = os.path.join(carpeta_posters, nombre_archivo)
                
                # Guardar archivo
                poster_file.save(ruta_archivo)
                update_data['archivo_poster'] = nombre_archivo
                
                flash('Póster actualizado exitosamente incluyendo el archivo PDF.', 'success')
            else:
                flash('Solo se permiten archivos PDF para el póster.', 'error')
                return render_template('editar_poster_admin.html', evento=evento, poster=poster)
        else:
            flash('Póster actualizado exitosamente.', 'success')
        
        # Actualizar en base de datos
        collection_posters.update_one(
            {"nanoid": nanoid_poster},
            {"$set": update_data}
        )
        
        # También actualizar en participantes si existe
        collection_participantes.update_one(
            {"nanoid": nanoid_poster},
            {"$set": {
                'nombres': nombres,
                'apellidos': apellidos,
                'perfil': institucion
            }}
        )
        
        # Crear mensaje de log detallado
        cambios = []
        if nombres != poster.get('nombres', ''):
            cambios.append('nombres')
        if apellidos != poster.get('apellidos', ''):
            cambios.append('apellidos')
        if titulo_poster != poster.get('titulo_poster', ''):
            cambios.append('título')
        if nueva_passphrase:
            cambios.append('passphrase')
        if poster_file and poster_file.filename:
            cambios.append('archivo PDF')
        
        cambios_str = ', '.join(cambios) if cambios else 'información general'
        log_event(f"Usuario [{current_user.email}] editó el póster #{poster['numero_poster']:02d} de {nombres} {apellidos} en el evento {codigo_evento}. Cambios: {cambios_str}.")
        
        return redirect(url_for('posters.admin_posters', codigo_evento=codigo_evento))
    
    return render_template('editar_poster_admin.html', evento=evento, poster=poster)