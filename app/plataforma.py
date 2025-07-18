from flask import Blueprint, render_template, request, redirect, url_for, abort, flash
from app import db, collection_eventos, collection_eva, collection_qbanks, collection_qbanks_data
from flask_login import login_required, current_user
from app.auth import token_required
from datetime import datetime
from werkzeug.utils import secure_filename
import os
import re
from bson import ObjectId

plataforma_bp = Blueprint('plataforma', __name__)


###
### LMS - Listado de actividades o contenidos
###
@plataforma_bp.route('/tablero/eventos/<codigo_evento>/lms')
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
@plataforma_bp.route('/tablero/eventos/<codigo_evento>/lms/nuevo', methods=['GET', 'POST'])
@login_required
def crear_contenido(codigo_evento):

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

        elif tipo == 'caso_chatgpt':
            try:
                import json
                contenido_json_raw = request.form['json_caso']
                # Intentar parsear el JSON para validarlo
                contenido_json = json.loads(contenido_json_raw)
                # Guardar el contenido como string para evitar problemas de codificación
                contenido['contenido_json'] = contenido_json_raw
            except Exception as e:
                flash('El JSON del caso clínico no es válido: ' + str(e), 'error')
                return redirect(request.url)

        elif tipo == 'examen':
            contenido['qbank_config'] = request.form['qbank_config']

        collection_eva.insert_one(contenido)

        return redirect(url_for('plataforma.listar_contenidos', codigo_evento=codigo_evento))

    return render_template('crear_contenido.html', evento=evento)


###
### LMS - Editar evento / contenio
###
@plataforma_bp.route('/tablero/eventos/<codigo_evento>/lms/<int:orden>/editar', methods=['GET', 'POST'])
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
        elif tipo == 'examen':
            actualizacion['qbank_config'] = request.form['qbank_config']

        collection_eva.update_one({'codigo_evento': codigo_evento, 'orden': orden}, {'$set': actualizacion})

        return redirect(url_for('plataforma.listar_contenidos', codigo_evento=codigo_evento))

    return render_template('editar_contenido.html', evento=evento, contenido=contenido)


###
### LMS - mover item de evento
###
@plataforma_bp.route('/tablero/eventos/<codigo_evento>/lms/<int:orden>/mover/<direccion>', methods=['POST'])
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
        return redirect(url_for('plataforma.listar_contenidos', codigo_evento=codigo_evento))

    # Intercambiar los órdenes en la base de datos
    collection_eva.update_one({'_id': contenido_actual['_id']}, {'$set': {'orden': nuevo_orden}})
    collection_eva.update_one({'_id': contenido_destino['_id']}, {'$set': {'orden': orden}})

    return redirect(url_for('plataforma.listar_contenidos', codigo_evento=codigo_evento))


###
### LMS - eliminar item de evento
###
@plataforma_bp.route('/tablero/eventos/<codigo_evento>/<int:orden>/eliminar', methods=['POST'])
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

    return redirect(url_for('plataforma.listar_contenidos', codigo_evento=codigo_evento))


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
@plataforma_bp.route('/plataforma/<codigo_evento>/<int:orden>', methods=['GET', 'POST'])
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

    # Mostrar examen si el tipo es 'examen' y tiene qbank_config
    if contenido_actual.get('tipo') == 'examen' and 'qbank_config' in contenido_actual:
        codigo_qbank, num_preguntas, aleatorio = parse_qbank_config(contenido_actual['qbank_config'])
        if codigo_qbank:
            if request.method == 'POST':
                # Recuperar los IDs de las preguntas del campo oculto
                preguntas_ids = request.form.get('preguntas_ids', '').split(',')
                preguntas = [collection_qbanks_data.find_one({'_id': ObjectId(pid)}) for pid in preguntas_ids if pid]
            else:
                preguntas = list(collection_qbanks_data.find({'codigo_qbank': codigo_qbank}))
                import random
                if aleatorio:
                    preguntas = random.sample(preguntas, min(num_preguntas, len(preguntas)))
                else:
                    preguntas = preguntas[:num_preguntas]
            puntaje = None
            if request.method == 'POST':
                correctas = 0
                for i, pregunta in enumerate(preguntas):
                    respuesta_usuario = request.form.getlist(f'resp_{i}')
                    if set(map(str, pregunta['respuestas_correctas'])) == set(respuesta_usuario):
                        correctas += 1
                puntaje = (correctas, len(preguntas))
            # Pasar los IDs de las preguntas al template para el campo oculto
            preguntas_ids = ','.join([str(p['_id']) for p in preguntas])
            return render_template('examen.html', preguntas=preguntas, puntaje=puntaje, contenido=contenido_actual, evento=evento, cedula=cedula, token=token, preguntas_ids=preguntas_ids)

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


###
### Listado de Bancos de Preguntas
###
@plataforma_bp.route('/tablero/qbanks/')
@plataforma_bp.route('/tablero/qbanks/page/<int:page>')
@login_required
def listar_qbank(page=1):
    qbanks_por_pagina = 20  # Número de qbanks por página

    # Contar el total de qbanks
    total_qbanks = collection_qbanks.count_documents({})
    
    # Calcular el número total de páginas
    total_paginas = (total_qbanks + qbanks_por_pagina - 1) // qbanks_por_pagina

    # Obtener los qbanks para la página actual
    qbanks_cursor = collection_qbanks.find().sort("fecha_creacion", -1).skip((page - 1) * qbanks_por_pagina).limit(qbanks_por_pagina)
    qbanks = list(qbanks_cursor)

    return render_template('qbanks_listar.html', 
        qbanks=qbanks,
        page=page,
        total_paginas=total_paginas,
        total_qbanks=total_qbanks
    )


###
### Crear nuevo Banco de Preguntas
###
@plataforma_bp.route('/tablero/qbanks/nuevo', methods=['GET', 'POST'])
@login_required
def nuevo_qbank():
    if request.method == 'POST':
        # Obtener datos del formulario
        qbank_titulo = request.form.get('qbank_titulo', '').strip()
        qbank_descripcion = request.form.get('qbank_descripcion', '').strip()
        qbank_tags = request.form.get('qbank_tags', '').strip()
        timestamp = request.form.get('timestamp', '')
        
        # Validaciones básicas
        if not qbank_titulo:
            flash('El título del banco de preguntas es obligatorio.', 'error')
            return render_template('qbanks_nuevo.html')
        
        if not qbank_descripcion:
            flash('La descripción del banco de preguntas es obligatoria.', 'error')
            return render_template('qbanks_nuevo.html')
        
        # Generar código único para el qbank (similar al de eventos)
        def generar_codigo_qbank(longitud=8):
            import random
            import string
            caracteres = string.ascii_uppercase + string.digits
            codigo = ''.join(random.choice(caracteres) for _ in range(longitud))
            return codigo

        def obtener_codigo_unico_qbank():
            while True:
                codigo = generar_codigo_qbank()
                if collection_qbanks.find_one({"codigo": codigo}) is None:
                    return codigo
        
        codigo_qbank = obtener_codigo_unico_qbank()
        
        # Procesar tags (convertir string a lista)
        tags_list = []
        if qbank_tags:
            tags_list = [tag.strip() for tag in qbank_tags.split(',') if tag.strip()]
        
        # Crear documento del qbank
        qbank_data = {
            'codigo': codigo_qbank,
            'titulo': qbank_titulo,
            'descripcion': qbank_descripcion,
            'tags': tags_list,
            'autor': current_user.id,
            'autor_email': current_user.email,
            'fecha_creacion': datetime.now(),
            'fecha_modificacion': datetime.now(),
            'activo': True,
            'total_preguntas': 0
        }
        
        try:
            # Insertar en la base de datos
            result = collection_qbanks.insert_one(qbank_data)
            
            if result.inserted_id:
                flash(f'Banco de preguntas "{qbank_titulo}" creado exitosamente con código: {codigo_qbank}', 'success')
                return redirect(url_for('plataforma.ver_qbank', codigo_qbank=codigo_qbank))
            else:
                flash('Error al crear el banco de preguntas.', 'error')
                
        except Exception as e:
            flash(f'Error al guardar en la base de datos: {str(e)}', 'error')
            print(f"Error en nuevo_qbank: {str(e)}")  # Para debugging
    
    # Para GET o si hay errores, mostrar el formulario
    return render_template('qbanks_nuevo.html')


###
### Ver un Banco de Preguntas
###
@plataforma_bp.route('/tablero/qbanks/<codigo_qbank>')
@login_required
def ver_qbank(codigo_qbank):
    # Buscar el qbank en la base de datos
    qbank = collection_qbanks.find_one({"codigo": codigo_qbank})
    
    if not qbank:
        flash('Banco de preguntas no encontrado.', 'error')
        return redirect(url_for('plataforma.listar_qbank'))
    
    # Buscar las preguntas asociadas a este banco
    preguntas = list(collection_qbanks_data.find({"codigo_qbank": codigo_qbank}))
        
    return render_template('qbanks_ver.html', qbank=qbank, preguntas=preguntas)


###
### Eliminar un Banco de Preguntas
###
@plataforma_bp.route('/tablero/qbanks/<codigo_qbank>/eliminar', methods=['POST'])
@login_required
def eliminar_qbank(codigo_qbank):
    # Buscar el qbank en la base de datos
    qbank = collection_qbanks.find_one({"codigo": codigo_qbank})
    
    if not qbank:
        flash('Banco de preguntas no encontrado.', 'error')
        return redirect(url_for('plataforma.listar_qbank'))
    
    # Verificar que el usuario sea el autor del qbank o administrador
    if qbank.get('autor') != current_user.id and current_user.rol != 'administrador':
        flash('No tienes permisos para eliminar este banco de preguntas.', 'error')
        return redirect(url_for('plataforma.listar_qbank'))
    
    try:
        # Eliminar el qbank
        result = collection_qbanks.delete_one({"codigo": codigo_qbank})
        
        if result.deleted_count > 0:
            flash(f'Banco de preguntas "{qbank["titulo"]}" eliminado exitosamente.', 'success')
        else:
            flash('Error al eliminar el banco de preguntas.', 'error')
            
    except Exception as e:
        flash(f'Error al eliminar el banco de preguntas: {str(e)}', 'error')
        print(f"Error en eliminar_qbank: {str(e)}")  # Para debugging
    
    return redirect(url_for('plataforma.listar_qbank'))


# from flask import jsonify, request
# from openai import OpenAI
# import os

# # Inicializar el cliente OpenAI
# ## client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

# client = OpenAI(
#     api_key=os.environ.get("OPENROUTER_API_KEY"),
#     base_url="https://openrouter.ai/api/v1",
#     default_headers={
#         "HTTP-Referer": "http://localhost",  # o el dominio real
#         "X-Title": "Simulador Clínico"
#     }
# )

# @plataforma_bp.route('/api/chat_contenido/<codigo_evento>/<int:orden>', methods=['POST'])
# def chat_contenido(codigo_evento, orden):
#     try:
#         # Verificar que se recibió el JSON
#         if not request.json:
#             return jsonify({'error': 'No se recibió datos JSON'}), 400
            
#         user_input = request.json.get('mensaje')
#         if not user_input:
#             return jsonify({'error': 'Mensaje vacío'}), 400

#         # Buscar el contenido
#         contenido = collection_eva.find_one({'codigo_evento': codigo_evento, 'orden': orden})

#         if not contenido or contenido['tipo'] != 'caso_chatgpt':
#             return jsonify({'error': 'Contenido no encontrado o no válido'}), 400

#         if 'contenido_json' not in contenido:
#             return jsonify({'error': 'El caso clínico no tiene contenido JSON válido'}), 400

#         # Preparar el prompt asegurando codificación UTF-8
#         caso_clinico = contenido['contenido_json']
#         if isinstance(caso_clinico, dict):
#             # Si es un diccionario, convertirlo a string
#             caso_clinico = str(caso_clinico)
        
#         prompt_base = f"""Este es un caso clínico de un curso en línea. El contenido es el siguiente:
#         José. Masculino de 55 años, DM2 de 8 años de evolución. Usa metformina 850 mg bid. Glicemia capilar en ayunas 425 mg/dl
#         HbA1C 9%.
#         Actúa como un tutor clínico. Responde a la siguiente pregunta del usuario basada únicamente en este caso:"""

#         # Llamada a OpenAI con la nueva API
#         response = client.chat.completions.create(
#             model="deepseek/deepseek-r1-0528:free",
#             messages=[
#                 {"role": "system", "content": prompt_base},
#                 {"role": "user", "content": user_input}
#             ],
#             max_tokens=1000,
#             temperature=0.7
#         )
        
#         respuesta = response.choices[0].message.content
#         return jsonify({'respuesta': respuesta})
        
#     except Exception as e:
#         print(f"Error en chat_contenido: {str(e)}")  # Para debugging
#         return jsonify({'error': f'Error interno: {str(e)}'}), 500


@plataforma_bp.route('/tablero/qbanks/<codigo_qbank>/nueva_pregunta', methods=['GET', 'POST'])
@login_required
def nueva_pregunta_qbank(codigo_qbank):
    if request.method == 'POST':
        tipo = request.form['tipo']
        pregunta_html = request.form['pregunta_html']
        justificacion_html = request.form['justificacion_html']
        opciones = []
        respuestas_correctas = request.form.getlist('respuestas_correctas')
        imagenes_pregunta = request.files.getlist('imagenes_pregunta')
        imagenes_opciones = request.files.getlist('imagenes_opciones')
        
        # Procesar opciones y sus imágenes
        for i in range(int(request.form['num_opciones'])):
            texto = request.form.get(f'opcion_texto_{i}', '')
            imagen = None
            if f'opcion_imagen_{i}' in request.files:
                file = request.files[f'opcion_imagen_{i}']
                if file and file.filename:
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    imagen = filename
            opciones.append({'texto': texto, 'imagen': imagen})
        
        # Guardar imágenes de la pregunta
        imagenes = []
        for file in imagenes_pregunta:
            if file and file.filename:
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                imagenes.append(filename)
        
        # Guardar en MongoDB
        collection_qbanks_data.insert_one({
            "codigo_qbank": codigo_qbank,
            "tipo": tipo,
            "pregunta_html": pregunta_html,
            "opciones": opciones,
            "respuestas_correctas": [int(idx) for idx in respuestas_correctas],
            "justificacion_html": justificacion_html,
            "imagenes": imagenes
        })
        flash('Pregunta guardada correctamente', 'success')
        return redirect(url_for('plataforma.ver_qbank', codigo_qbank=codigo_qbank))
    
    qbank = collection_qbanks.find_one({"codigo": codigo_qbank})

    return render_template('qbanks_pregunta_nueva.html', codigo_qbank=codigo_qbank, qbank=qbank)


def parse_qbank_config(config_str):
    # Ejemplo: [O5W4YTK2 preguntas=3 aleatorio=no]
    match = re.match(r'\[(\w+) preguntas=(\d+) aleatorio=(si|no)\]', config_str)
    if match:
        codigo = match.group(1)
        num_preguntas = int(match.group(2))
        aleatorio = match.group(3) == 'si'
        return codigo, num_preguntas, aleatorio
    return None, None, None