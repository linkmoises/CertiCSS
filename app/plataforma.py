import os
import re
from datetime import datetime

from bson import ObjectId
from flask import (
    Blueprint,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
    current_app,
)
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from app import (
    collection_eva,
    collection_eventos,
    collection_exam_results,
    collection_participantes,
    collection_qbanks,
    collection_qbanks_data,
    db,
)
from app.auth import token_required, lms_required, lms_edit_required

plataforma_bp = Blueprint("plataforma", __name__)


###
### LMS - Listado de actividades o contenidos
###
@plataforma_bp.route("/tablero/eventos/<codigo_evento>/lms")
@login_required
@lms_required
def listar_contenidos(codigo_evento):
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)

    actividades = collection_eva.find({"codigo_evento": codigo_evento}).sort("orden", 1)

    return render_template(
        "listar_contenido.html",
        codigo_evento=codigo_evento,
        evento=evento,
        actividades=actividades,
    )


###
### LMS - Crear actividad
###
@plataforma_bp.route(
    "/tablero/eventos/<codigo_evento>/lms/nuevo", methods=["GET", "POST"]
)
@login_required
@lms_required
def crear_contenido(codigo_evento):
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)

    if request.method == "POST":
        titulo = request.form["titulo"]
        descripcion = request.form["descripcion"]
        tipo = request.form["tipo"]

        # Obtener el próximo número en la secuencia
        ultimo_contenido = collection_eva.find_one(
            {"codigo_evento": codigo_evento}, sort=[("orden", -1)]
        )
        nuevo_orden = (ultimo_contenido["orden"] + 1) if ultimo_contenido else 1

        contenido = {
            "codigo_evento": codigo_evento,
            "orden": nuevo_orden,
            "titulo": titulo,
            "descripcion": descripcion,
            "tipo": tipo,
        }

        if tipo == "video":
            contenido["url_video"] = request.form["url_video"]

        elif tipo == "texto":
            contenido["contenido_texto"] = request.form["contenido_texto"]

        elif tipo == "documento":
            documento_file = request.files.get("documento")
            if documento_file:
                # Crear carpeta del evento si no existe
                evento_folder = os.path.join(current_app.config["UPLOAD_FOLDER"], codigo_evento)
                os.makedirs(evento_folder, exist_ok=True)
                
                # Generar nombre único para el documento
                extension = os.path.splitext(documento_file.filename)[1] or '.pdf'
                documento_filename = f"documento-{codigo_evento}-{nuevo_orden:02d}{extension}"
                documento_path = os.path.join(evento_folder, documento_filename)
                documento_file.save(documento_path)
                
                # Guardar la ruta relativa desde uploads
                contenido["documento"] = f"{codigo_evento}/{documento_filename}"

        elif tipo == "caso_chatgpt":
            try:
                import json

                contenido_json_raw = request.form["json_caso"]
                # Intentar parsear el JSON para validarlo
                contenido_json = json.loads(contenido_json_raw)
                # Guardar el contenido como string para evitar problemas de codificación
                contenido["contenido_json"] = contenido_json_raw
            except Exception as e:
                flash("El JSON del caso clínico no es válido: " + str(e), "error")
                return redirect(request.url)

        elif tipo == "examen":
            contenido["qbank_config"] = request.form["qbank_config"]

        collection_eva.insert_one(contenido)

        return redirect(
            url_for("plataforma.listar_contenidos", codigo_evento=codigo_evento)
        )

    return render_template("crear_contenido.html", evento=evento)


###
### LMS - Editar evento / contenio
###
@plataforma_bp.route(
    "/tablero/eventos/<codigo_evento>/lms/<int:orden>/editar", methods=["GET", "POST"]
)
@login_required
@lms_required
def editar_contenido(codigo_evento, orden):
    # # Obtener cédula y token de los parámetros
    # cedula = request.args.get('cedula')
    # token = request.args.get('token')

    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)

    contenido = collection_eva.find_one(
        {"codigo_evento": codigo_evento, "orden": orden}
    )
    if not contenido:
        abort(404)

    if request.method == "POST":
        titulo = request.form["titulo"]
        descripcion = request.form["descripcion"]
        tipo = request.form["tipo"]

        actualizacion = {"titulo": titulo, "descripcion": descripcion, "tipo": tipo}

        if tipo == "video":
            actualizacion["url_video"] = request.form["url_video"]
        elif tipo == "texto":
            actualizacion["contenido_texto"] = request.form["contenido_texto"]
        elif tipo == "documento":
            documento_file = request.files.get("documento")
            if documento_file:
                # Crear carpeta del evento si no existe
                evento_folder = os.path.join(current_app.config["UPLOAD_FOLDER"], codigo_evento)
                os.makedirs(evento_folder, exist_ok=True)
                
                # Generar nombre único para el documento
                extension = os.path.splitext(documento_file.filename)[1] or '.pdf'
                documento_filename = f"documento-{codigo_evento}-{orden:02d}{extension}"
                documento_path = os.path.join(evento_folder, documento_filename)
                documento_file.save(documento_path)
                
                # Guardar la ruta relativa desde uploads
                actualizacion["documento"] = f"{codigo_evento}/{documento_filename}"
        elif tipo == "caso_chatgpt":
            try:
                import json

                contenido_json_raw = request.form["json_caso"]
                # Intentar parsear el JSON para validarlo
                contenido_json = json.loads(contenido_json_raw)
                # Guardar el contenido como string para evitar problemas de codificación
                actualizacion["contenido_json"] = contenido_json_raw
            except Exception as e:
                flash("El JSON del caso clínico no es válido: " + str(e), "error")
                return redirect(request.url)
        elif tipo == "examen":
            actualizacion["qbank_config"] = request.form["qbank_config"]

        collection_eva.update_one(
            {"codigo_evento": codigo_evento, "orden": orden}, {"$set": actualizacion}
        )

        return redirect(
            url_for("plataforma.listar_contenidos", codigo_evento=codigo_evento)
        )

    return render_template("editar_contenido.html", evento=evento, contenido=contenido)


###
### LMS - previsualizar contenido
###
@plataforma_bp.route(
    "/tablero/eventos/<codigo_evento>/lms/<int:orden>/previsualizar", methods=["GET"]
)
@login_required
@lms_required
def previsualizar_contenido(codigo_evento, orden):
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)

    contenido = collection_eva.find_one(
        {"codigo_evento": codigo_evento, "orden": orden}
    )
    if not contenido:
        abort(404)

    # Obtener la lista completa de contenidos para el sidebar
    contenidos = list(
        collection_eva.find({"codigo_evento": codigo_evento}).sort("orden", 1)
    )

    # Convertir Markdown a HTML solo si el tipo es 'texto'
    import markdown

    if contenido.get("tipo") == "texto" and "contenido_texto" in contenido:
        contenido["contenido_texto"] = markdown.markdown(contenido["contenido_texto"])

    # Si es examen, cargar las preguntas para la previsualización
    preguntas = []
    if contenido.get("tipo") == "examen" and "qbank_config" in contenido:
        codigo_qbank, num_preguntas, aleatorio = parse_qbank_config(
            contenido["qbank_config"]
        )
        if codigo_qbank:
            preguntas = list(
                collection_qbanks_data.find({"codigo_qbank": codigo_qbank})
            )
            import random

            if aleatorio:
                preguntas = random.sample(preguntas, min(num_preguntas, len(preguntas)))
            else:
                preguntas = preguntas[:num_preguntas]

    return render_template(
        "plataforma_previsualizar.html",
        evento=evento,
        contenido_actual=contenido,
        contenidos=contenidos,
        preguntas=preguntas,
    )


###
### LMS - mover item de evento
###
@plataforma_bp.route(
    "/tablero/eventos/<codigo_evento>/lms/<int:orden>/mover/<direccion>",
    methods=["POST"],
)
@login_required
@lms_required
def mover_contenido(codigo_evento, orden, direccion):
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)

    contenido_actual = collection_eva.find_one(
        {"codigo_evento": codigo_evento, "orden": orden}
    )
    if not contenido_actual:
        abort(404)

    # Determinar la nueva posición
    nuevo_orden = orden - 1 if direccion == "arriba" else orden + 1

    contenido_destino = collection_eva.find_one(
        {"codigo_evento": codigo_evento, "orden": nuevo_orden}
    )
    if not contenido_destino:
        return redirect(
            url_for("plataforma.listar_contenidos", codigo_evento=codigo_evento)
        )

    # Intercambiar los órdenes en la base de datos
    collection_eva.update_one(
        {"_id": contenido_actual["_id"]}, {"$set": {"orden": nuevo_orden}}
    )
    collection_eva.update_one(
        {"_id": contenido_destino["_id"]}, {"$set": {"orden": orden}}
    )

    return redirect(
        url_for("plataforma.listar_contenidos", codigo_evento=codigo_evento)
    )


###
### LMS - eliminar item de evento
###
@plataforma_bp.route(
    "/tablero/eventos/<codigo_evento>/<int:orden>/eliminar", methods=["POST"]
)
@login_required
@lms_required
def eliminar_contenido(codigo_evento, orden):
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)

    contenido = collection_eva.find_one(
        {"codigo_evento": codigo_evento, "orden": orden}
    )
    if not contenido:
        abort(404)

    collection_eva.delete_one({"codigo_evento": codigo_evento, "orden": orden})

    # Reordenar los elementos después de la eliminación
    contenidos_restantes = list(
        collection_eva.find({"codigo_evento": codigo_evento}).sort("orden", 1)
    )
    for i, cont in enumerate(contenidos_restantes, start=1):
        collection_eva.update_one({"_id": cont["_id"]}, {"$set": {"orden": i}})

    return redirect(
        url_for("plataforma.listar_contenidos", codigo_evento=codigo_evento)
    )


###
### LMS - Landing page de un evento virtual
###
@plataforma_bp.route("/plataforma/<codigo_evento>")
# @token_required
def ver_plataforma(codigo_evento):
    # Obtener cédula y token de los parámetros
    cedula = request.args.get("cedula")
    token = request.args.get("token")

    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)

    primer_contenido = collection_eva.find_one(
        {"codigo_evento": codigo_evento}, sort=[("orden", 1)]
    )

    if primer_contenido:
        return redirect(
            url_for(
                "plataforma.ver_contenido",
                codigo_evento=codigo_evento,
                orden=primer_contenido["orden"],
                cedula=cedula,
                token=token,
            )
        )
    else:
        return render_template(
            "plataforma.html",
            evento=evento,
            contenidos=[],
            contenido_actual=None,
            cedula=cedula,
            token=token,
        )


###
### LMS - Renderiza los contenidos de un evento virtual
###
import markdown


@plataforma_bp.route("/plataforma/<codigo_evento>/<int:orden>", methods=["GET", "POST"])
@token_required
def ver_contenido(codigo_evento, orden):
    # Obtener cédula y token de los parámetros
    cedula = request.args.get("cedula")
    token = request.args.get("token")

    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)

    # Obtener la lista completa de contenidos ordenados
    contenidos = list(
        collection_eva.find({"codigo_evento": codigo_evento}).sort("orden", 1)
    )

    # Buscar el contenido actual
    contenido_actual = next((c for c in contenidos if c["orden"] == orden), None)
    if not contenido_actual:
        abort(404)

    # Convertir Markdown a HTML solo si el tipo es 'texto'
    if (
        contenido_actual.get("tipo") == "texto"
        and "contenido_texto" in contenido_actual
    ):
        contenido_actual["contenido_texto"] = markdown.markdown(
            contenido_actual["contenido_texto"]
        )

    # Mostrar examen si el tipo es 'examen' y tiene qbank_config
    if contenido_actual.get("tipo") == "examen" and "qbank_config" in contenido_actual:
        codigo_qbank, num_preguntas, aleatorio = parse_qbank_config(
            contenido_actual["qbank_config"]
        )
        if codigo_qbank:
            if request.method == "POST":
                # Recuperar los IDs de las preguntas del campo oculto
                preguntas_ids = request.form.get("preguntas_ids", "").split(",")
                preguntas = [
                    collection_qbanks_data.find_one({"_id": ObjectId(pid)})
                    for pid in preguntas_ids
                    if pid
                ]
            else:
                preguntas = list(
                    collection_qbanks_data.find({"codigo_qbank": codigo_qbank})
                )
                import random

                if aleatorio:
                    preguntas = random.sample(
                        preguntas, min(num_preguntas, len(preguntas))
                    )
                else:
                    preguntas = preguntas[:num_preguntas]
            puntaje = None
            if request.method == "POST":
                correctas = 0
                respuestas_usuario = []
                for i, pregunta in enumerate(preguntas):
                    respuesta_usuario = request.form.getlist(f"resp_{i}")
                    respuestas_usuario.append(
                        {
                            "pregunta_id": str(pregunta["_id"]),
                            "respuesta": respuesta_usuario,
                            "correcta": set(map(str, pregunta["respuestas_correctas"]))
                            == set(respuesta_usuario),
                        }
                    )
                    if set(map(str, pregunta["respuestas_correctas"])) == set(
                        respuesta_usuario
                    ):
                        correctas += 1
                puntaje = (correctas, len(preguntas))

                # Calcular calificación como porcentaje
                calificacion = (
                    (correctas / len(preguntas)) * 100 if len(preguntas) > 0 else 0
                )

                # Obtener cédula del participante desde los parámetros
                cedula_participante = request.args.get("cedula")

                # Verificar que el evento es Virtual asincrónica antes de guardar
                if (
                    evento.get("modalidad") == "Virtual asincrónica"
                    and cedula_participante
                ):
                    # Obtener el número de intento (contar intentos previos + 1)
                    intentos_previos = collection_exam_results.count_documents(
                        {
                            "codigo_evento": codigo_evento,
                            "orden_examen": orden,
                            "cedula_participante": cedula_participante,
                        }
                    )

                    numero_intento = intentos_previos + 1

                    # Crear el documento de resultado
                    resultado_examen = {
                        "codigo_evento": codigo_evento,
                        "orden_examen": orden,
                        "cedula_participante": cedula_participante,
                        "numero_intento": numero_intento,
                        "calificacion": calificacion,
                        "respuestas": respuestas_usuario,
                        "fecha_envio": datetime.now(),
                        "titulo_examen": contenido_actual.get("titulo", "Sin título"),
                        "titulo_evento": evento.get("titulo", "Sin título"),
                        "total_preguntas": len(preguntas),
                        "respuestas_correctas": correctas,
                    }

                    # Insertar el resultado en la base de datos
                    try:
                        collection_exam_results.insert_one(resultado_examen)
                    except Exception as e:
                        print(f"Error al guardar resultado del examen: {e}")
            # Pasar los IDs de las preguntas al template para el campo oculto
            preguntas_ids = ",".join([str(p["_id"]) for p in preguntas])

            # Buscar el nanoid del participante para el enlace del certificado
            participante = collection_participantes.find_one(
                {
                    "cedula": cedula,
                    "codigo_evento": codigo_evento,
                    "rol": "participante",
                }
            )
            nanoid = participante.get("nanoid") if participante else None

            return render_template(
                "examen.html",
                preguntas=preguntas,
                puntaje=puntaje,
                contenido=contenido_actual,
                contenido_actual=contenido_actual,
                evento=evento,
                cedula=cedula,
                token=token,
                preguntas_ids=preguntas_ids,
                nanoid=nanoid,
                contenidos=contenidos,
            )

    # Encontrar el contenido anterior y el siguiente
    indice_actual = contenidos.index(contenido_actual)
    contenido_anterior = contenidos[indice_actual - 1] if indice_actual > 0 else None
    contenido_siguiente = (
        contenidos[indice_actual + 1] if indice_actual < len(contenidos) - 1 else None
    )

    return render_template(
        "plataforma.html",
        evento=evento,
        contenidos=contenidos,
        contenido_actual=contenido_actual,
        contenido_anterior=contenido_anterior,
        contenido_siguiente=contenido_siguiente,
        cedula=cedula,
        token=token,
    )


###
### Listado de Bancos de Preguntas
###
@plataforma_bp.route("/tablero/qbanks/")
@plataforma_bp.route("/tablero/qbanks/page/<int:page>")
@login_required
@lms_edit_required
def listar_qbank(page=1):
    qbanks_por_pagina = 20  # Número de qbanks por página

    # Verificar permisos del usuario
    permisos_usuario = getattr(current_user, 'permisos', [])
    es_admin_completo = (
        current_user.rol in ['administrador', 'denadoi'] or 
        'lms_admin' in permisos_usuario
    )
    
    # Si tiene lms_edit (no admin completo), solo mostrar sus propios QBanks
    if not es_admin_completo and 'lms_edit' in permisos_usuario:
        filtro = {"autor": current_user.id}
    else:
        filtro = {}

    # Contar el total de qbanks
    total_qbanks = collection_qbanks.count_documents(filtro)

    # Calcular el número total de páginas
    total_paginas = (total_qbanks + qbanks_por_pagina - 1) // qbanks_por_pagina

    # Obtener los qbanks para la página actual
    qbanks_cursor = (
        collection_qbanks.find(filtro)
        .sort("fecha_creacion", -1)
        .skip((page - 1) * qbanks_por_pagina)
        .limit(qbanks_por_pagina)
    )
    qbanks = list(qbanks_cursor)

    # Cargar las preguntas para cada qbank
    for qbank in qbanks:
        qbank["preguntas"] = list(
            collection_qbanks_data.find({"codigo_qbank": qbank["codigo"]})
        )

    return render_template(
        "qbanks_listar.html",
        qbanks=qbanks,
        page=page,
        total_paginas=total_paginas,
        total_qbanks=total_qbanks,
    )


###
### Crear nuevo Banco de Preguntas
###
@plataforma_bp.route("/tablero/qbanks/nuevo", methods=["GET", "POST"])
@login_required
@lms_edit_required
def nuevo_qbank():
    if request.method == "POST":
        # Obtener datos del formulario
        qbank_titulo = request.form.get("qbank_titulo", "").strip()
        qbank_descripcion = request.form.get("qbank_descripcion", "").strip()
        qbank_tags = request.form.get("qbank_tags", "").strip()
        timestamp = request.form.get("timestamp", "")

        # Validaciones básicas
        if not qbank_titulo:
            flash("El título del banco de preguntas es obligatorio.", "error")
            return render_template("qbanks_nuevo.html")

        if not qbank_descripcion:
            flash("La descripción del banco de preguntas es obligatoria.", "error")
            return render_template("qbanks_nuevo.html")

        # Generar código único para el qbank (similar al de eventos)
        def generar_codigo_qbank(longitud=8):
            import random
            import string

            caracteres = string.ascii_uppercase + string.digits
            codigo = "".join(random.choice(caracteres) for _ in range(longitud))
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
            tags_list = [tag.strip() for tag in qbank_tags.split(",") if tag.strip()]

        # Crear documento del qbank
        qbank_data = {
            "codigo": codigo_qbank,
            "titulo": qbank_titulo,
            "descripcion": qbank_descripcion,
            "tags": tags_list,
            "autor": current_user.id,
            "autor_email": current_user.email,
            "fecha_creacion": datetime.now(),
            "fecha_modificacion": datetime.now(),
            "activo": True,
            "total_preguntas": 0,
        }

        try:
            # Insertar en la base de datos
            result = collection_qbanks.insert_one(qbank_data)

            if result.inserted_id:
                flash(
                    f'Banco de preguntas "{qbank_titulo}" creado exitosamente con código: {codigo_qbank}',
                    "success",
                )
                return redirect(
                    url_for("plataforma.ver_qbank", codigo_qbank=codigo_qbank)
                )
            else:
                flash("Error al crear el banco de preguntas.", "error")

        except Exception as e:
            flash(f"Error al guardar en la base de datos: {str(e)}", "error")
            print(f"Error en nuevo_qbank: {str(e)}")  # Para debugging

    # Para GET o si hay errores, mostrar el formulario
    return render_template("qbanks_nuevo.html")


###
### Editar un banco de preguntas
###
@plataforma_bp.route("/tablero/qbanks/<codigo_qbank>/editar", methods=["GET", "POST"])
@login_required
@lms_edit_required
def editar_qbank(codigo_qbank):
    # Buscar el qbank en la base de datos
    qbank = collection_qbanks.find_one({"codigo": codigo_qbank})

    if not qbank:
        flash("Banco de preguntas no encontrado.", "error")
        return redirect(url_for("plataforma.listar_qbank"))

    if request.method == "POST":
        titulo = request.form.get("qbank_titulo", "").strip()
        descripcion = request.form.get("qbank_descripcion", "").strip()
        qbank_tags = request.form.get("qbank_tags", "").strip()

        # Validaciones básicas
        if not titulo:
            flash("El título es obligatorio.", "error")
            return render_template("qbanks_editar.html", qbank=qbank)

        # Procesar tags (convertir string a lista)
        tags_list = []
        if qbank_tags:
            tags_list = [tag.strip() for tag in qbank_tags.split(",") if tag.strip()]

        try:
            # Update qbank
            update_data = {
                "titulo": titulo,
                "descripcion": descripcion,
                "tags": tags_list,
                "fecha_modificacion": datetime.now(),
            }

            collection_qbanks.update_one(
                {"codigo": codigo_qbank}, {"$set": update_data}
            )

            flash("Banco de preguntas actualizado exitosamente.", "success")
            return redirect(url_for("plataforma.listar_qbank"))
        except Exception as e:
            flash(f"Error al actualizar el banco de preguntas: {str(e)}", "error")
            print(f"Error en editar_qbank: {str(e)}")

    # Normalizar las tags para el template (asegurar que sea una lista)
    if qbank.get("tags"):
        if isinstance(qbank["tags"], str):
            # Si es string, convertir a lista
            qbank["tags"] = [
                tag.strip() for tag in qbank["tags"].split(",") if tag.strip()
            ]
        elif not isinstance(qbank["tags"], list):
            # Si no es lista ni string, convertir a lista vacía
            qbank["tags"] = []
    else:
        # Si no existe o es None, establecer como lista vacía
        qbank["tags"] = []

    # Para GET o si hay errores, mostrar el formulario
    return render_template("qbanks_editar.html", qbank=qbank)


###
### Ver QBank completo
###
@plataforma_bp.route("/tablero/qbanks/<codigo_qbank>")
@login_required
@lms_edit_required
def ver_qbank(codigo_qbank):
    # Buscar el qbank en la base de datos
    qbank = collection_qbanks.find_one({"codigo": codigo_qbank})

    if not qbank:
        flash("Banco de preguntas no encontrado.", "error")
        return redirect(url_for("plataforma.listar_qbank"))

    # Buscar las preguntas asociadas a este banco
    preguntas = list(collection_qbanks_data.find({"codigo_qbank": codigo_qbank}))

    return render_template("qbanks_ver.html", qbank=qbank, preguntas=preguntas)


###
### Eliminar un Banco de Preguntas
###
@plataforma_bp.route("/tablero/qbanks/<codigo_qbank>/eliminar", methods=["POST"])
@login_required
@lms_edit_required
def eliminar_qbank(codigo_qbank):
    # Buscar el qbank en la base de datos
    qbank = collection_qbanks.find_one({"codigo": codigo_qbank})

    if not qbank:
        flash("Banco de preguntas no encontrado.", "error")
        return redirect(url_for("plataforma.listar_qbank"))

    # Verificar que el usuario sea el autor del qbank o administrador
    if qbank.get("autor") != current_user.id and current_user.rol != "administrador":
        flash("No tienes permisos para eliminar este banco de preguntas.", "error")
        return redirect(url_for("plataforma.listar_qbank"))

    # Verificar si hay preguntas asociadas al qbank
    preguntas_count = collection_qbanks_data.count_documents(
        {"codigo_qbank": codigo_qbank}
    )
    if preguntas_count > 0:
        flash(
            f"No se puede eliminar el banco de preguntas porque tiene {preguntas_count} pregunta(s) asociada(s). Elimine todas las preguntas primero.",
            "error",
        )
        return redirect(url_for("plataforma.listar_qbank"))

    try:
        # Eliminar el qbank
        result = collection_qbanks.delete_one({"codigo": codigo_qbank})

        if result.deleted_count > 0:
            flash(
                f'Banco de preguntas "{qbank["titulo"]}" eliminado exitosamente.',
                "success",
            )
        else:
            flash("Error al eliminar el banco de preguntas.", "error")

    except Exception as e:
        flash(f"Error al eliminar el banco de preguntas: {str(e)}", "error")
        print(f"Error en eliminar_qbank: {str(e)}")  # Para debugging

    return redirect(url_for("plataforma.listar_qbank"))


###
### Editar una pregunta de un Banco de Preguntas
###
@plataforma_bp.route(
    "/tablero/qbanks/<codigo_qbank>/editar_pregunta/<pregunta_id>",
    methods=["GET", "POST"],
)
@login_required
@lms_edit_required
def editar_pregunta_qbank(codigo_qbank, pregunta_id):
    # Buscar el qbank en la base de datos
    qbank = collection_qbanks.find_one({"codigo": codigo_qbank})

    if not qbank:
        flash("Banco de preguntas no encontrado.", "error")
        return redirect(url_for("plataforma.listar_qbank"))

    # Verificar que el usuario sea el autor del qbank o administrador
    if qbank.get("autor") != current_user.id and current_user.rol != "administrador":
        flash(
            "No tienes permisos para editar preguntas de este banco de preguntas.",
            "error",
        )
        return redirect(url_for("plataforma.ver_qbank", codigo_qbank=codigo_qbank))

    # Buscar la pregunta
    pregunta = collection_qbanks_data.find_one(
        {"_id": ObjectId(pregunta_id), "codigo_qbank": codigo_qbank}
    )

    if not pregunta:
        flash("Pregunta no encontrada.", "error")
        return redirect(url_for("plataforma.ver_qbank", codigo_qbank=codigo_qbank))

    if request.method == "POST":
        tipo = request.form["tipo"]
        pregunta_html = request.form["pregunta_html"]
        justificacion_html = request.form["justificacion_html"]
        respuestas_correctas = request.form.getlist("respuestas_correctas")
        imagenes_pregunta = request.files.getlist("imagenes_pregunta")

        # Crear carpeta del evento si no existe
        evento_folder = os.path.join(current_app.config["UPLOAD_FOLDER"], codigo_qbank)
        os.makedirs(evento_folder, exist_ok=True)
        
        # Obtener el contador actual de archivos en la carpeta
        existing_files = [f for f in os.listdir(evento_folder) if f.startswith(f"archivo-{codigo_qbank}-")]
        archivo_counter = len(existing_files) + 1
        
        # Función para generar nombre único de archivo
        def generar_nombre_archivo(original_filename, counter):
            extension = os.path.splitext(original_filename)[1]
            return f"archivo-{codigo_qbank}-{counter}{extension}"

        # Procesar opciones
        opciones = []
        for i in range(int(request.form["num_opciones"])):
            texto = request.form.get(f"opcion_texto_{i}", "")
            imagen = None

            # Verificar si se subió una nueva imagen
            if f"opcion_imagen_{i}" in request.files:
                file = request.files[f"opcion_imagen_{i}"]
                if file and file.filename:
                    filename = generar_nombre_archivo(file.filename, archivo_counter)
                    archivo_counter += 1
                    file_path = os.path.join(evento_folder, filename)
                    file.save(file_path)
                    # Guardar la ruta relativa desde uploads
                    imagen = f"{codigo_qbank}/{filename}"

            # Si no se subió nueva imagen, intentar mantener la existente
            if not imagen:
                imagen = request.form.get(f"opcion_imagen_actual_{i}")

            opciones.append({"texto": texto, "imagen": imagen})

        # Guardar imágenes de la pregunta (solo si se suben nuevas)
        imagenes = pregunta.get("imagenes", [])  # Mantener imágenes existentes
        for file in imagenes_pregunta:
            if file and file.filename:
                filename = generar_nombre_archivo(file.filename, archivo_counter)
                archivo_counter += 1
                file_path = os.path.join(evento_folder, filename)
                file.save(file_path)
                # Guardar la ruta relativa desde uploads
                imagenes.append(f"{codigo_qbank}/{filename}")

        # Actualizar en MongoDB
        actualizacion = {
            "tipo": tipo,
            "pregunta_html": pregunta_html,
            "opciones": opciones,
            "respuestas_correctas": [int(idx) for idx in respuestas_correctas],
            "justificacion_html": justificacion_html,
            "imagenes": imagenes,
        }

        try:
            result = collection_qbanks_data.update_one(
                {"_id": ObjectId(pregunta_id)}, {"$set": actualizacion}
            )

            if result.modified_count > 0:
                flash("Pregunta actualizada exitosamente.", "success")
            else:
                flash("No se realizaron cambios en la pregunta.", "info")

        except Exception as e:
            flash(f"Error al actualizar la pregunta: {str(e)}", "error")
            print(f"Error en editar_pregunta_qbank: {str(e)}")  # Para debugging

        return redirect(url_for("plataforma.ver_qbank", codigo_qbank=codigo_qbank))

    # Para GET, mostrar el formulario con los datos existentes
    return render_template(
        "qbanks_pregunta_editar.html",
        codigo_qbank=codigo_qbank,
        qbank=qbank,
        pregunta=pregunta,
    )


###
### Eliminar una pregunta de un Banco de Preguntas
###
@plataforma_bp.route(
    "/tablero/qbanks/<codigo_qbank>/eliminar_pregunta/<pregunta_id>", methods=["POST"]
)
@login_required
@lms_edit_required
def eliminar_pregunta_qbank(codigo_qbank, pregunta_id):
    # Buscar el qbank en la base de datos
    qbank = collection_qbanks.find_one({"codigo": codigo_qbank})

    if not qbank:
        flash("Banco de preguntas no encontrado.", "error")
        return redirect(url_for("plataforma.listar_qbank"))

    # Verificar que el usuario sea el autor del qbank o administrador
    if qbank.get("autor") != current_user.id and current_user.rol != "administrador":
        flash(
            "No tienes permisos para eliminar preguntas de este banco de preguntas.",
            "error",
        )
        return redirect(url_for("plataforma.ver_qbank", codigo_qbank=codigo_qbank))

    try:
        # Buscar la pregunta
        pregunta = collection_qbanks_data.find_one(
            {"_id": ObjectId(pregunta_id), "codigo_qbank": codigo_qbank}
        )

        if not pregunta:
            flash("Pregunta no encontrada.", "error")
            return redirect(url_for("plataforma.ver_qbank", codigo_qbank=codigo_qbank))

        # Eliminar la pregunta
        result = collection_qbanks_data.delete_one({"_id": ObjectId(pregunta_id)})

        if result.deleted_count > 0:
            # Actualizar el contador de preguntas en el qbank
            total_preguntas = collection_qbanks_data.count_documents(
                {"codigo_qbank": codigo_qbank}
            )
            collection_qbanks.update_one(
                {"codigo": codigo_qbank}, {"$set": {"total_preguntas": total_preguntas}}
            )

            flash("Pregunta eliminada exitosamente.", "success")
        else:
            flash("Error al eliminar la pregunta.", "error")

    except Exception as e:
        flash(f"Error al eliminar la pregunta: {str(e)}", "error")
        print(f"Error en eliminar_pregunta_qbank: {str(e)}")  # Para debugging

    return redirect(url_for("plataforma.ver_qbank", codigo_qbank=codigo_qbank))


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


@plataforma_bp.route(
    "/tablero/qbanks/<codigo_qbank>/nueva_pregunta", methods=["GET", "POST"]
)
@login_required
@lms_edit_required
def nueva_pregunta_qbank(codigo_qbank):
    if request.method == "POST":
        tipo = request.form["tipo"]
        pregunta_html = request.form["pregunta_html"]
        justificacion_html = request.form["justificacion_html"]
        opciones = []
        respuestas_correctas = request.form.getlist("respuestas_correctas")
        imagenes_pregunta = request.files.getlist("imagenes_pregunta")
        imagenes_opciones = request.files.getlist("imagenes_opciones")

        # Crear carpeta del evento si no existe
        evento_folder = os.path.join(current_app.config["UPLOAD_FOLDER"], codigo_qbank)
        os.makedirs(evento_folder, exist_ok=True)
        
        # Contador para archivos únicos
        archivo_counter = 1
        
        # Función para generar nombre único de archivo
        def generar_nombre_archivo(original_filename, counter):
            extension = os.path.splitext(original_filename)[1]
            return f"archivo-{codigo_qbank}-{counter}{extension}"
        
        # Procesar opciones y sus imágenes
        for i in range(int(request.form["num_opciones"])):
            texto = request.form.get(f"opcion_texto_{i}", "")
            imagen = None
            if f"opcion_imagen_{i}" in request.files:
                file = request.files[f"opcion_imagen_{i}"]
                if file and file.filename:
                    filename = generar_nombre_archivo(file.filename, archivo_counter)
                    archivo_counter += 1
                    file_path = os.path.join(evento_folder, filename)
                    file.save(file_path)
                    # Guardar la ruta relativa desde uploads
                    imagen = f"{codigo_qbank}/{filename}"
            opciones.append({"texto": texto, "imagen": imagen})

        # Guardar imágenes de la pregunta
        imagenes = []
        for file in imagenes_pregunta:
            if file and file.filename:
                filename = generar_nombre_archivo(file.filename, archivo_counter)
                archivo_counter += 1
                file_path = os.path.join(evento_folder, filename)
                file.save(file_path)
                # Guardar la ruta relativa desde uploads
                imagenes.append(f"{codigo_qbank}/{filename}")

        # Guardar en MongoDB
        collection_qbanks_data.insert_one(
            {
                "codigo_qbank": codigo_qbank,
                "tipo": tipo,
                "pregunta_html": pregunta_html,
                "opciones": opciones,
                "respuestas_correctas": [int(idx) for idx in respuestas_correctas],
                "justificacion_html": justificacion_html,
                "imagenes": imagenes,
            }
        )
        flash("Pregunta guardada correctamente", "success")
        return redirect(url_for("plataforma.ver_qbank", codigo_qbank=codigo_qbank))

    qbank = collection_qbanks.find_one({"codigo": codigo_qbank})

    return render_template(
        "qbanks_pregunta_nueva.html", codigo_qbank=codigo_qbank, qbank=qbank
    )


def parse_qbank_config(config_str):
    # Ejemplo: [O5W4YTK2 preguntas=3 aleatorio=no]
    match = re.match(r"\[(\w+) preguntas=(\d+) aleatorio=(si|no)\]", config_str)
    if match:
        codigo = match.group(1)
        num_preguntas = int(match.group(2))
        aleatorio = match.group(3) == "si"
        return codigo, num_preguntas, aleatorio
    return None, None, None


###
### Endpoint para enviar resultados de exámenes
###
@plataforma_bp.route("/api/examen/enviar", methods=["POST"])
@token_required
def enviar_resultado_examen():
    """
    Endpoint para almacenar los resultados de un examen.
    Espera los siguientes datos en JSON:
    - codigo_evento: código del evento
    - orden_examen: orden del examen en el evento
    - respuestas: lista de respuestas del usuario
    - calificacion: calificación obtenida (0-100)
    - cedula_participante: cédula del participante
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No se recibieron datos"}), 400

        codigo_evento = data.get("codigo_evento")
        orden_examen = data.get("orden_examen")
        respuestas = data.get("respuestas", [])
        calificacion = data.get("calificacion", 0)
        cedula_participante = data.get("cedula_participante")

        # Validar datos requeridos
        if not all([codigo_evento, orden_examen is not None, cedula_participante]):
            return jsonify({"error": "Faltan datos requeridos"}), 400

        # Verificar que el evento existe y es Virtual asincrónica
        evento = collection_eventos.find_one(
            {"codigo": codigo_evento, "modalidad": "Virtual asincrónica"}
        )

        if not evento:
            return jsonify(
                {"error": "Evento no encontrado o no es Virtual asincrónica"}
            ), 404

        # Verificar que el examen existe
        examen = collection_eva.find_one(
            {"codigo_evento": codigo_evento, "orden": orden_examen, "tipo": "examen"}
        )

        if not examen:
            return jsonify({"error": "Examen no encontrado"}), 404

        # Verificar que el participante está registrado en el evento
        participante = collection_participantes.find_one(
            {
                "codigo_evento": codigo_evento,
                "cedula": cedula_participante,
                "rol": "participante",
            }
        )

        if not participante:
            return jsonify({"error": "Participante no registrado en el evento"}), 403

        # Obtener el número de intento (contar intentos previos + 1)
        intentos_previos = collection_exam_results.count_documents(
            {
                "codigo_evento": codigo_evento,
                "orden_examen": orden_examen,
                "cedula_participante": cedula_participante,
            }
        )

        numero_intento = intentos_previos + 1

        # Crear el documento de resultado
        resultado_examen = {
            "codigo_evento": codigo_evento,
            "orden_examen": orden_examen,
            "cedula_participante": cedula_participante,
            "numero_intento": numero_intento,
            "calificacion": float(calificacion),
            "respuestas": respuestas,
            "fecha_envio": datetime.now(),
            "titulo_examen": examen.get("titulo", "Sin título"),
            "titulo_evento": evento.get("titulo", "Sin título"),
        }

        # Insertar el resultado en la base de datos
        result = collection_exam_results.insert_one(resultado_examen)

        if result.inserted_id:
            return jsonify(
                {
                    "success": True,
                    "message": "Resultado guardado correctamente",
                    "numero_intento": numero_intento,
                    "calificacion": calificacion,
                }
            ), 200
        else:
            return jsonify({"error": "Error al guardar el resultado"}), 500

    except Exception as e:
        return jsonify({"error": f"Error interno: {str(e)}"}), 500


###
### Endpoint para obtener historial de intentos de un participante
###
@plataforma_bp.route(
    "/api/examen/historial/<codigo_evento>/<int:orden_examen>/<cedula_participante>"
)
@token_required
def obtener_historial_examen(codigo_evento, orden_examen, cedula_participante):
    """
    Obtiene el historial de intentos de un participante en un examen específico.
    """
    try:
        # Verificar que el evento existe
        evento = collection_eventos.find_one({"codigo": codigo_evento})
        if not evento:
            return jsonify({"error": "Evento no encontrado"}), 404

        # Obtener todos los intentos del participante para este examen
        intentos = list(
            collection_exam_results.find(
                {
                    "codigo_evento": codigo_evento,
                    "orden_examen": orden_examen,
                    "cedula_participante": cedula_participante,
                }
            ).sort("numero_intento", 1)
        )

        # Formatear los datos para la respuesta
        historial = []
        for intento in intentos:
            historial.append(
                {
                    "numero_intento": intento["numero_intento"],
                    "calificacion": intento["calificacion"],
                    "fecha_envio": intento["fecha_envio"].isoformat()
                    if intento.get("fecha_envio")
                    else None,
                    "respuestas": intento.get("respuestas", []),
                }
            )

        # Calcular estadísticas
        if historial:
            mejor_calificacion = max(h["calificacion"] for h in historial)
            promedio_calificacion = sum(h["calificacion"] for h in historial) / len(
                historial
            )
            total_intentos = len(historial)
        else:
            mejor_calificacion = 0
            promedio_calificacion = 0
            total_intentos = 0

        return jsonify(
            {
                "historial": historial,
                "estadisticas": {
                    "total_intentos": total_intentos,
                    "mejor_calificacion": mejor_calificacion,
                    "promedio_calificacion": round(promedio_calificacion, 2),
                },
            }
        ), 200

    except Exception as e:
        return jsonify({"error": f"Error interno: {str(e)}"}), 500
