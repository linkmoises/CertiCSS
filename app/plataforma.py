from flask import Blueprint, render_template, request, redirect, url_for, abort, flash
from app import db, collection_eventos, collection_eva
from flask_login import login_required, current_user
from app.auth import token_required

plataforma_bp = Blueprint('plataforma', __name__)


###
### LMS - Listado de actividades o contenidos
###
@plataforma_bp.route('/lms/<codigo_evento>/')
@login_required
def listar_contenidos(codigo_evento):

    evento = collection_eventos.find_one({'codigo': codigo_evento})
    if not evento:
        abort(404)

    actividades = collection_eva.find({'codigo_evento': codigo_evento}).sort('orden', 1)

    return render_template('listar_contenido.html', codigo_evento=codigo_evento, evento=evento, actividades=actividades)


###
### LMS - Crear actividad
###
@plataforma_bp.route('/lms/<codigo_evento>/nuevo', methods=['GET', 'POST'])
@login_required
def crear_contenido(codigo_evento):
    # # Obtener cédula y token de los parámetros
    # cedula = request.args.get('cedula')
    # token = request.args.get('token')

    evento = collection_eventos.find_one({'codigo': codigo_evento})
    if not evento:
        abort(404)

    if request.method == 'POST':
        titulo = request.form['titulo']
        descripcion = request.form['descripcion']
        tipo = request.form['tipo']

        # Obtener el próximo número en la secuencia
        ultimo_contenido = collection_eva.find_one({'codigo_evento': codigo_evento}, sort=[("orden", -1)])
        nuevo_orden = (ultimo_contenido['orden'] + 1) if ultimo_contenido else 1

        contenido = {
            'codigo_evento': codigo_evento,
            'orden': nuevo_orden,
            'titulo': titulo,
            'descripcion': descripcion,
            'tipo': tipo
        }

        if tipo == 'video':
            contenido['url_video'] = request.form['url_video']

        elif tipo == 'texto':
            contenido['contenido_texto'] = request.form['contenido_texto']

        elif tipo == 'documento':
            documento_file = request.files.get('documento')
            if documento_file:
                documento_filename = f"{codigo_evento}-{nuevo_orden:02d}.pdf"
                documento_path = os.path.join(app.config['UPLOAD_FOLDER'], documento_filename)
                documento_file.save(documento_path)
                contenido['documento'] = documento_filename

        collection_eva.insert_one(contenido)

        return redirect(url_for('plataforma.ver_plataforma', codigo_evento=codigo_evento, cedula=cedula, token=token))

    return render_template('crear_contenido.html', evento=evento)


###
### LMS - Editar evento / contenio
###
@plataforma_bp.route('/lms/<codigo_evento>/<int:orden>/editar', methods=['GET', 'POST'])
@login_required
def editar_contenido(codigo_evento, orden):
    # # Obtener cédula y token de los parámetros
    # cedula = request.args.get('cedula')
    # token = request.args.get('token')

    evento = collection_eventos.find_one({'codigo': codigo_evento})
    if not evento:
        abort(404)

    contenido = collection_eva.find_one({'codigo_evento': codigo_evento, 'orden': orden})
    if not contenido:
        abort(404)

    if request.method == 'POST':
        titulo = request.form['titulo']
        descripcion = request.form['descripcion']
        tipo = request.form['tipo']

        actualizacion = {
            'titulo': titulo,
            'descripcion': descripcion,
            'tipo': tipo
        }

        if tipo == 'video':
            actualizacion['url_video'] = request.form['url_video']
        elif tipo == 'texto':
            actualizacion['contenido_texto'] = request.form['contenido_texto']
        elif tipo == 'documento':
            documento_file = request.files.get('documento')
            if documento_file:
                documento_filename = f"{codigo_evento}-{orden:02d}.pdf"
                documento_path = os.path.join(app.config['UPLOAD_FOLDER'], documento_filename)
                documento_file.save(documento_path)
                actualizacion['documento'] = documento_filename

        collection_eva.update_one({'codigo_evento': codigo_evento, 'orden': orden}, {'$set': actualizacion})

        return redirect(url_for('ver_contenido', codigo_evento=codigo_evento, orden=orden, cedula=cedula, token=token))

    return render_template('editar_contenido.html', evento=evento, contenido=contenido)


###
### LMS - mover item de evento
###
@plataforma_bp.route('/lms/<codigo_evento>/<int:orden>/mover/<direccion>', methods=['POST'])
@login_required
def mover_contenido(codigo_evento, orden, direccion):
    evento = collection_eventos.find_one({'codigo': codigo_evento})
    if not evento:
        abort(404)

    contenido_actual = collection_eva.find_one({'codigo_evento': codigo_evento, 'orden': orden})
    if not contenido_actual:
        abort(404)

    # Determinar la nueva posición
    nuevo_orden = orden - 1 if direccion == 'arriba' else orden + 1

    contenido_destino = collection_eva.find_one({'codigo_evento': codigo_evento, 'orden': nuevo_orden})
    if not contenido_destino:
        return redirect(url_for('plataforma.ver_plataforma', codigo_evento=codigo_evento))  # Si no hay contenido en esa dirección, no hacer nada

    # Intercambiar los órdenes en la base de datos
    collection_eva.update_one({'_id': contenido_actual['_id']}, {'$set': {'orden': nuevo_orden}})
    collection_eva.update_one({'_id': contenido_destino['_id']}, {'$set': {'orden': orden}})

    return redirect(url_for('plataforma.ver_plataforma', codigo_evento=codigo_evento))


###
### LMS - eliminar item de evento
###
@plataforma_bp.route('/lms/<codigo_evento>/<int:orden>/eliminar', methods=['POST'])
@login_required
def eliminar_contenido(codigo_evento, orden):
    evento = collection_eventos.find_one({'codigo': codigo_evento})
    if not evento:
        abort(404)

    contenido = collection_eva.find_one({'codigo_evento': codigo_evento, 'orden': orden})
    if not contenido:
        abort(404)

    collection_eva.delete_one({'codigo_evento': codigo_evento, 'orden': orden})

    # Reordenar los elementos después de la eliminación
    contenidos_restantes = list(collection_eva.find({'codigo_evento': codigo_evento}).sort('orden', 1))
    for i, cont in enumerate(contenidos_restantes, start=1):
        collection_eva.update_one({'_id': cont['_id']}, {'$set': {'orden': i}})

    return redirect(url_for('ver_plataforma', codigo_evento=codigo_evento))


###
### LMS - Landing page de un evento virtual
###
@plataforma_bp.route('/plataforma/<codigo_evento>')
# @token_required
def ver_plataforma(codigo_evento):
    # Obtener cédula y token de los parámetros
    cedula = request.args.get('cedula')
    token = request.args.get('token')

    evento = collection_eventos.find_one({'codigo': codigo_evento})
    if not evento:
        abort(404)

    primer_contenido = collection_eva.find_one({'codigo_evento': codigo_evento}, sort=[("orden", 1)])

    if primer_contenido:
        return redirect(url_for('plataforma.ver_contenido', codigo_evento=codigo_evento, orden=primer_contenido['orden'], cedula=cedula, token=token))
    else:
        return render_template('plataforma.html', evento=evento, contenidos=[], contenido_actual=None, cedula=cedula, token=token)


###
### LMS - Renderiza los contenidos de un evento virtual
###
import markdown
@plataforma_bp.route('/plataforma/<codigo_evento>/<int:orden>')
@token_required
def ver_contenido(codigo_evento, orden):
    # Obtener cédula y token de los parámetros
    cedula = request.args.get('cedula')
    token = request.args.get('token')

    evento = collection_eventos.find_one({'codigo': codigo_evento})
    if not evento:
        abort(404)

    # Obtener la lista completa de contenidos ordenados
    contenidos = list(collection_eva.find({'codigo_evento': codigo_evento}).sort('orden', 1))
    
    # Buscar el contenido actual
    contenido_actual = next((c for c in contenidos if c['orden'] == orden), None)
    if not contenido_actual:
        abort(404)
        
    # Convertir Markdown a HTML solo si el tipo es 'texto'
    if contenido_actual.get('tipo') == 'texto' and 'contenido_texto' in contenido_actual:
        contenido_actual['contenido_texto'] = markdown.markdown(contenido_actual['contenido_texto'])

    # Encontrar el contenido anterior y el siguiente
    indice_actual = contenidos.index(contenido_actual)
    contenido_anterior = contenidos[indice_actual - 1] if indice_actual > 0 else None
    contenido_siguiente = contenidos[indice_actual + 1] if indice_actual < len(contenidos) - 1 else None

    return render_template(
        'plataforma.html',
        evento=evento,
        contenidos=contenidos,
        contenido_actual=contenido_actual,
        contenido_anterior=contenido_anterior,
        contenido_siguiente=contenido_siguiente,
        cedula=cedula, 
        token=token
    )

