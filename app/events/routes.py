from flask import Blueprint, request, redirect, url_for, flash, render_template, jsonify, abort
from flask_login import current_user, login_required
from datetime import datetime, timedelta
from bson.objectid import ObjectId

from app.auth.services import roles_required, UserRole
from app.logs import log_event

events_bp = Blueprint('events', __name__, url_prefix='/tablero')


def init_events_routes():
    pass


@events_bp.route('/eventos/proximos')
@events_bp.route('/tablero/eventos/proximos/page/<int:page>')
@login_required
def listar_eventos_proximos(page=1):
    from app.events.services import (
        get_collection_eventos, 
        get_collection_participantes,
        get_collection_usuarios,
        paginate_events
    )
    from app.events import services
    
    eventos_por_pagina = 20
    filtro_eventos = {
        'fecha_inicio': {'$gte': datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)},
        'registro_abierto': {'$ne': True}
    }
    
    eventos, total_eventos, total_paginas = paginate_events(
        get_collection_eventos(), 
        filtro_eventos, 
        page, 
        eventos_por_pagina
    )
    
    collection_participantes = get_collection_participantes()
    collection_usuarios = get_collection_usuarios()
    
    for evento in eventos:
        es_organizador = collection_participantes.find_one({
            "codigo_evento": evento["codigo"],
            "cedula": str(current_user.cedula),
            "rol": "coorganizador"
        }) is not None 
        evento["es_organizador"] = es_organizador
        
        if evento.get("autor"):
            evento["autor_info"] = collection_usuarios.find_one(
                {"_id": ObjectId(evento["autor"])},
                {"nombres": 1, "apellidos": 1, "foto": 1}
            )
    
    return render_template('eventos-proximos.html',
        eventos=eventos,
        page=page,
        total_paginas=total_paginas,
        total_eventos=total_eventos
    )


@events_bp.route('/eventos/anteriores')
@events_bp.route('/eventos/anteriores/page/<int:page>')
@login_required
def listar_eventos_anteriores(page=1):
    from app.events.services import (
        get_collection_eventos, 
        get_collection_participantes,
        get_collection_usuarios,
        paginate_events
    )
    
    eventos_por_pagina = 20
    filtro_eventos = {
        "fecha_inicio": {"$lt": datetime.utcnow()},
        'registro_abierto': {'$ne': True}
    }
    
    eventos, total_eventos, total_paginas = paginate_events(
        get_collection_eventos(),
        filtro_eventos, 
        page, 
        eventos_por_pagina,
        sort_field="fecha_inicio",
        sort_order=-1
    )
    
    collection_participantes = get_collection_participantes()
    collection_usuarios = get_collection_usuarios()
    
    for evento in eventos:
        es_organizador = collection_participantes.find_one({
            "codigo_evento": evento["codigo"],
            "cedula": str(current_user.cedula),
            "rol": "coorganizador"
        }) is not None 
        evento["es_organizador"] = es_organizador
        
        if evento.get("autor"):
            evento["autor_info"] = collection_usuarios.find_one(
                {"_id": ObjectId(evento["autor"])},
                {"nombres": 1, "apellidos": 1, "foto": 1}
            )
    
    return render_template('eventos-anteriores.html',
        eventos=eventos,
        page=page,
        total_paginas=total_paginas,
        total_eventos=total_eventos
    )


@events_bp.route('/eventos')
@events_bp.route('/eventos/page/<int:page>')
@login_required
def listar_eventos(page=1):
    from app.events.services import (
        get_collection_eventos, 
        get_collection_participantes,
        get_collection_usuarios,
        paginate_events
    )
    
    eventos_por_pagina = 20
    filtro_eventos = {
        'registro_abierto': {'$ne': True},
        'tipo': {'$ne': 'Sesión Docente'}
    }
    
    eventos, total_eventos, total_paginas = paginate_events(
        get_collection_eventos(),
        filtro_eventos, 
        page, 
        eventos_por_pagina,
        sort_field="fecha_inicio",
        sort_order=-1
    )
    
    collection_participantes = get_collection_participantes()
    collection_usuarios = get_collection_usuarios()
    
    for evento in eventos:
        es_organizador = collection_participantes.find_one({
            "codigo_evento": evento["codigo"],
            "cedula": str(current_user.cedula),
            "rol": "coorganizador"
        }) is not None 
        evento["es_organizador"] = es_organizador
        
        if evento.get("autor"):
            evento["autor_info"] = collection_usuarios.find_one(
                {"_id": ObjectId(evento["autor"])},
                {"nombres": 1, "apellidos": 1, "foto": 1}
            )
    
    return render_template('eventos.html',
        eventos=eventos,
        total_eventos=total_eventos,
        page=page,
        total_paginas=total_paginas
    )


@events_bp.route('/eventos/mios')
@events_bp.route('/eventos/mios/page/<int:page>')
@login_required
def mis_eventos(page=1):
    from app.events.services import (
        get_collection_eventos, 
        get_collection_participantes,
        get_collection_usuarios,
        paginate_events
    )
    
    eventos_por_pagina = 20
    filtro = {
        "autor": current_user.id,
        'registro_abierto': {'$ne': True}
    }
    
    eventos, total_eventos, total_paginas = paginate_events(
        get_collection_eventos(),
        filtro, 
        page, 
        eventos_por_pagina,
        sort_field="fecha_inicio",
        sort_order=-1
    )
    
    collection_participantes = get_collection_participantes()
    
    for evento in eventos:
        es_organizador = collection_participantes.find_one({
            "codigo_evento": evento["codigo"],
            "cedula": str(current_user.cedula),
            "rol": "coorganizador"
        }) is not None 
        evento["es_organizador"] = es_organizador
    
    return render_template('mis_eventos.html',
        eventos=eventos,
        total_eventos=total_eventos,
        page=page,
        total_paginas=total_paginas
    )


@events_bp.route('/eventos/nuevo', methods=['GET', 'POST'])
@login_required
def crear_evento():
    from app.events.services import obtener_codigo_unico, get_collection_eventos
    from app import app
    import os
    from PIL import Image
    
    prefill = {}
    if request.args:
        prefill = {
            'nombre': request.args.get('nombre', ''),
            'region': request.args.get('region', ''),
            'unidad_ejecutora': request.args.get('unidad_ejecutora', ''),
            'lugar': request.args.get('lugar', ''),
            'modalidad': request.args.get('modalidad', ''),
            'tipo': request.args.get('tipo', ''),
            'cupos': request.args.get('cupos', ''),
            'carga_horaria': request.args.get('carga_horaria', ''),
            'descripcion': request.args.get('descripcion', ''),
        }

    if request.method == 'POST':
        nombre = request.form['nombre']
        region = request.form['region']
        unidad_ejecutora = request.form['unidad_ejecutora']
        lugar = request.form['lugar']
        tipo = request.form['tipo']
        cupos = request.form['cupos']
        carga_horaria = request.form['carga_horaria']
        modalidad = request.form['modalidad']
        descripcion = request.form['descripcion']
        checkin_masivo = request.form.get('checkin_masivo') == 'on'
        concurso_poster = request.form.get('concurso_poster') == 'on'
        registro_abierto = request.form.get('registro_abierto') == 'on'
        avales = request.form.getlist('aval')

        fecha_inicio_str = request.form['fecha_inicio']
        fecha_fin_str = request.form['fecha_fin']

        fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%dT%H:%M')
        fecha_fin = datetime.strptime(fecha_fin_str, '%Y-%m-%dT%H:%M')

        estado_evento = request.form['estado_evento']
        timestamp = request.form['timestamp']
        instrumento = request.form.get('instrumento', 'encuesta_v2')

        codigo = obtener_codigo_unico(get_collection_eventos())

        afiche_file = request.files.get('afiche_evento')
        fondo_file = request.files.get('fondo_evento')
        programa_file = request.files.get('programa_evento')
        certificado_file = request.files.get('certificado_evento')
        constancia_file = request.files.get('constancia_evento')

        afiche_path = None
        fondo_path = None
        programa_path = None
        certificado_path = None
        constancia_path = None
        resized_afiche_path = None

        upload_folder = app.config['UPLOAD_FOLDER']

        if afiche_file:
            afiche_filename = f"{codigo}-afiche.jpg"
            afiche_path = os.path.join(upload_folder, afiche_filename)

            image = Image.open(afiche_file)
            image.convert('RGB').save(afiche_path, 'JPEG')

            image.thumbnail((750, 750))
            resized_afiche_path = os.path.join(upload_folder, f"{codigo}-afiche-750.jpg")
            image.save(resized_afiche_path, 'JPEG')

        if fondo_file:
            fondo_filename = f"{codigo}-fondo.jpg"
            fondo_path = os.path.join(upload_folder, fondo_filename)

            image = Image.open(fondo_file)
            image.convert('RGB').save(fondo_path, 'JPEG')

        if programa_file:
            programa_filename = f"{codigo}-programa.pdf"
            programa_path = os.path.join(upload_folder, programa_filename)
            programa_file.save(programa_path)

        if certificado_file:
            certificado_filename = f"{codigo}-certificado.pdf"
            certificado_path = os.path.join(upload_folder, certificado_filename)
            certificado_file.save(certificado_path)

        if constancia_file:
            constancia_filename = f"{codigo}-constancia.pdf"
            constancia_path = os.path.join(upload_folder, constancia_filename)
            constancia_file.save(constancia_path)

        get_collection_eventos().insert_one({
            'nombre': nombre,
            'codigo': codigo,
            'region': region,
            'unidad_ejecutora': unidad_ejecutora,
            'lugar': lugar,
            'tipo': tipo,
            'modalidad': modalidad,
            'descripcion': descripcion,
            'cupos': cupos,
            'carga_horaria': carga_horaria,
            'fecha_inicio': fecha_inicio,
            'fecha_fin': fecha_fin,
            'estado_evento': estado_evento,
            'afiche': afiche_path if afiche_file else None,
            'afiche_750': resized_afiche_path if afiche_file else None,
            'fondo': fondo_path if fondo_file else None,
            'programa': programa_path if programa_file else None,
            'certificado': certificado_path if certificado_file else None,
            'constancia': constancia_path if constancia_file else None,
            'timestamp': timestamp,
            'autor': current_user.id,
            'checkin_masivo': checkin_masivo,
            'concurso_poster': concurso_poster,
            'registro_abierto': registro_abierto,
            'avales': avales,
            'instrumento': instrumento
        })
        
        log_event(f"Usuario [{current_user.email}] ha creado el evento {codigo} exitosamente.")
        return redirect(url_for('mis_eventos'))

    return render_template('crear_evento.html', prefill=prefill)


@events_bp.route('/eventos/<codigo_evento>/copiar')
@login_required
def copiar_evento(codigo_evento):
    from app.events.services import get_event_by_code
    
    evento = get_event_by_code(get_collection_eventos(), codigo_evento)
    
    if not evento:
        flash("Evento no encontrado", "danger")
        return redirect(url_for('listar_eventos'))
    
    campos_copiar = {
        'nombre': evento.get('nombre', ''),
        'region': evento.get('region', ''),
        'unidad_ejecutora': evento.get('unidad_ejecutora', ''),
        'lugar': evento.get('lugar', ''),
        'modalidad': evento.get('modalidad', ''),
        'tipo': evento.get('tipo', ''),
        'cupos': evento.get('cupos', ''),
        'carga_horaria': evento.get('carga_horaria', ''),
        'descripcion': evento.get('descripcion', ''),
    }
    
    return redirect(url_for('crear_evento', **campos_copiar))


@events_bp.route('/eventos/<codigo_evento>')
@login_required
def ver_evento(codigo_evento):
    from app.events.services import get_event_by_code, get_collection_eventos
    
    evento = get_event_by_code(get_collection_eventos(), codigo_evento)
    
    if not evento:
        abort(404)
    
    from app.events.services import get_collection_participantes, get_collection_usuarios
    from app import validate_certificate_template, validate_attendance_template
    
    collection_participantes = get_collection_participantes()
    collection_usuarios = get_collection_usuarios()
    
    es_organizador = collection_participantes.find_one({
        "codigo_evento": codigo_evento,
        "cedula": str(current_user.cedula),
        "rol": "coorganizador"
    }) is not None
    evento["es_organizador"] = es_organizador

    autor_evento = None
    if evento.get("autor"):
        autor_evento = collection_usuarios.find_one(
            {"_id": ObjectId(evento["autor"])},
            {"nombres": 1, "apellidos": 1, "email": 1}
        )

    usuarios = None
    if current_user.rol == 'administrador':
        usuarios = list(collection_usuarios.find(
            {"rol": {"$ne": "administrador"}},
            {"nombres": 1, "apellidos": 1, "email": 1}
        ).sort([("nombres", 1), ("apellidos", 1)]))

    return render_template('ver_evento.html', 
        evento=evento, 
        validate_certificate_template=validate_certificate_template, 
        validate_attendance_template=validate_attendance_template, 
        usuarios=usuarios, 
        autor_evento=autor_evento
    )


@events_bp.route('/eventos/<codigo_evento>/cambiar_autor', methods=['POST'])
@login_required
def cambiar_autor_evento(codigo_evento):
    from app.events.services import get_event_by_code, get_collection_eventos, get_collection_usuarios
    
    if current_user.rol != 'administrador':
        flash("No tienes permisos para realizar esta acción", "danger")
        return redirect(url_for('ver_evento', codigo_evento=codigo_evento))
    
    nuevo_autor_id = request.form.get('nuevo_autor_id')
    if not nuevo_autor_id:
        flash("Selecciona un usuario", "danger")
        return redirect(url_for('ver_evento', codigo_evento=codigo_evento))
    
    evento = get_event_by_code(get_collection_eventos(), codigo_evento)
    if not evento:
        flash("Evento no encontrado", "danger")
        return redirect(url_for('listar_eventos'))
    
    nuevo_autor = get_collection_usuarios().find_one({"_id": ObjectId(nuevo_autor_id)})
    if not nuevo_autor:
        flash("Usuario no encontrado", "danger")
        return redirect(url_for('ver_evento', codigo_evento=codigo_evento))
    
    get_collection_eventos().update_one(
        {"codigo": codigo_evento},
        {"$set": {"autor": nuevo_autor_id}}
    )
    
    flash(f"Autor cambiado a {nuevo_autor.get('nombres', '')} {nuevo_autor.get('apellidos', '')} ({nuevo_autor.get('email', '')})", "success")
    return redirect(url_for('ver_evento', codigo_evento=codigo_evento))


@events_bp.route('/eventos/<codigo_evento>/editar', methods=['GET', 'POST'])
@login_required
def editar_evento(codigo_evento):
    from app.events.services import get_event_by_code, get_collection_eventos, check_user_can_edit_event, get_collection_participantes
    from app import app
    import os
    from PIL import Image
    
    evento = get_event_by_code(get_collection_eventos(), codigo_evento)
    
    if not evento:
        flash("Evento no encontrado", "danger")
        return redirect(url_for('listar_eventos'))
    
    if not check_user_can_edit_event(evento, current_user, get_collection_participantes()):
        flash("No tienes permisos para editar este evento", "danger")
        return redirect(url_for('ver_evento', codigo_evento=codigo_evento))
    
    if request.method == 'POST':
        nombre = request.form['nombre']
        region = request.form['region']
        unidad_ejecutora = request.form['unidad_ejecutora']
        lugar = request.form['lugar']
        tipo = request.form['tipo']
        modalidad = request.form['modalidad']
        descripcion = request.form['descripcion']
        cupos = request.form['cupos']
        carga_horaria = request.form['carga_horaria']
        checkin_masivo = request.form.get('checkin_masivo') == 'on'
        concurso_poster = request.form.get('concurso_poster') == 'on'
        registro_abierto = request.form.get('registro_abierto') == 'on'
        avales = request.form.getlist('aval')
        aval_cmp_tipo = request.form.get('aval_cmp_tipo')
        aval_cmp_horas = request.form.get('aval_cmp_horas')
        aval_cmp_codigo = request.form.get('aval_cmp_codigo')
        fecha_inicio_str = request.form['fecha_inicio']
        fecha_fin_str = request.form['fecha_fin']
        
        fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%dT%H:%M')
        fecha_fin = datetime.strptime(fecha_fin_str, '%Y-%m-%dT%H:%M')
        
        estado_evento = request.form['estado_evento']
        timestamp = request.form['timestamp']
        
        afiche_file = request.files.get('afiche_evento')
        fondo_file = request.files.get('fondo_evento')
        programa_file = request.files.get('programa_evento')
        certificado_file = request.files.get('certificado_evento')
        constancia_file = request.files.get('constancia_evento')
        
        afiche_path = evento.get('afiche')
        fondo_path = evento.get('fondo')
        resized_afiche_path = evento.get('afiche_750')
        programa_path = evento.get('programa')
        certificado_path = evento.get('certificado')
        constancia_path = evento.get('constancia')
        
        upload_folder = app.config['UPLOAD_FOLDER']
        
        if afiche_file:
            afiche_filename = f"{codigo_evento}-afiche.jpg"
            afiche_path = os.path.join(upload_folder, afiche_filename)
            
            image = Image.open(afiche_file)
            image.convert('RGB').save(afiche_path, 'JPEG')
            
            image.thumbnail((750, 750))
            resized_afiche_path = os.path.join(upload_folder, f"{codigo_evento}-afiche-750.jpg")
            image.save(resized_afiche_path, 'JPEG')
        
        if fondo_file:
            fondo_filename = f"{codigo_evento}-fondo.jpg"
            fondo_path = os.path.join(upload_folder, fondo_filename)
            
            image = Image.open(fondo_file)
            image.convert('RGB').save(fondo_path, 'JPEG')
        
        if programa_file:
            programa_filename = f"{codigo_evento}-programa.pdf"
            programa_path = os.path.join(upload_folder, programa_filename)
            programa_file.save(programa_path)
        
        if certificado_file:
            certificado_filename = f"{codigo_evento}-certificado.pdf"
            certificado_path = os.path.join(upload_folder, certificado_filename)
            certificado_file.save(certificado_path)
        
        if constancia_file:
            constancia_filename = f"{codigo_evento}-constancia.pdf"
            constancia_path = os.path.join(upload_folder, constancia_filename)
            constancia_file.save(constancia_path)
        
        update_data = {
            'nombre': nombre,
            'region': region,
            'unidad_ejecutora': unidad_ejecutora,
            'lugar': lugar,
            'tipo': tipo,
            'modalidad': modalidad,
            'descripcion': descripcion,
            'cupos': cupos,
            'carga_horaria': carga_horaria,
            'fecha_inicio': fecha_inicio,
            'fecha_fin': fecha_fin,
            'estado_evento': estado_evento,
            'afiche': afiche_path,
            'afiche_750': resized_afiche_path,
            'fondo': fondo_path,
            'programa': programa_path,
            'certificado': certificado_path,
            'constancia': constancia_path,
            'timestamp': timestamp,
            'checkin_masivo': checkin_masivo,
            'concurso_poster': concurso_poster,
            'registro_abierto': registro_abierto,
            'avales': avales,
            'aval_cmp_tipo': aval_cmp_tipo,
            'aval_cmp_horas': aval_cmp_horas,
            'aval_cmp_codigo': aval_cmp_codigo
        }
        
        get_collection_eventos().update_one(
            {"codigo": codigo_evento},
            {"$set": update_data}
        )
        
        log_event(f"Usuario [{current_user.email}] ha editado el evento {codigo_evento}.")
        return redirect(url_for('ver_evento', codigo_evento=codigo_evento))
    
    return render_template('editar_evento.html', evento=evento)


@events_bp.route('/eventos/<codigo_evento>/cerrar', methods=['POST'])
@login_required
def cerrar_evento(codigo_evento):
    from app.events.services import get_event_by_code, get_collection_eventos, check_user_can_edit_event, get_collection_participantes
    
    evento = get_event_by_code(get_collection_eventos(), codigo_evento)
    if not evento:
        flash("Evento no encontrado", "danger")
        return redirect(url_for('listar_eventos'))
    
    if not check_user_can_edit_event(evento, current_user, get_collection_participantes()):
        flash("No tienes permisos para cerrar este evento", "danger")
        return redirect(url_for('ver_evento', codigo_evento=codigo_evento))
    
    get_collection_eventos().update_one(
        {"codigo": codigo_evento},
        {"$set": {"estado_evento": "cerrado"}}
    )
    
    log_event(f"Usuario [{current_user.email}] ha cerrado el evento {codigo_evento}.")
    flash(f"Evento {codigo_evento} cerrado exitosamente.", "success")
    return redirect(url_for('ver_evento', codigo_evento=codigo_evento))


@events_bp.route('/eventos/<codigo_evento>/eliminar', methods=['POST'])
@login_required
def eliminar_evento(codigo_evento):
    from app.events.services import get_event_by_code, get_collection_eventos, get_collection_participantes
    
    evento = get_event_by_code(get_collection_eventos(), codigo_evento)
    if not evento:
        flash("Evento no encontrado", "danger")
        return redirect(url_for('listar_eventos'))
    
    if current_user.rol != 'administrador':
        flash("No tienes permisos para eliminar este evento", "danger")
        return redirect(url_for('ver_evento', codigo_evento=codigo_evento))
    
    get_collection_eventos().delete_one({"codigo": codigo_evento})
    
    log_event(f"Usuario [{current_user.email}] ha eliminado el evento {codigo_evento}.")
    flash(f"Evento {codigo_evento} eliminado exitosamente.", "success")
    return redirect(url_for('listar_eventos'))


@events_bp.route('/eventos/digitales')
@events_bp.route('/eventos/digitales/page/<int:page>')
@login_required
def listar_eventos_digitales(page=1):
    from app.events.services import (
        get_collection_eventos, 
        get_collection_participantes,
        paginate_events
    )
    
    eventos_por_pagina = 20
    filtro = {
        "autor": current_user.id,
        "modalidad": {"$ne": "Presencial"},
        'registro_abierto': {'$ne': True}
    }
    
    eventos, total_eventos, total_paginas = paginate_events(
        get_collection_eventos(),
        filtro, 
        page, 
        eventos_por_pagina,
        sort_field="fecha_inicio",
        sort_order=-1
    )
    
    collection_participantes = get_collection_participantes()
    
    for evento in eventos:
        es_organizador = collection_participantes.find_one({
            "codigo_evento": evento["codigo"],
            "cedula": str(current_user.cedula),
            "rol": "coorganizador"
        }) is not None 
        evento["es_organizador"] = es_organizador
    
    return render_template('mis_eventos_digitales.html',
        eventos=eventos,
        total_eventos=total_eventos,
        page=page,
        total_paginas=total_paginas
    )


@events_bp.route('/eventos/sesiones')
@events_bp.route('/eventos/sesiones/page/<int:page>')
@login_required
def mis_sesiones_docentes(page=1):
    from app.events.services import (
        get_collection_eventos, 
        get_collection_participantes,
        paginate_events
    )
    
    eventos_por_pagina = 20
    filtro = {
        "autor": current_user.id,
        'registro_abierto': {'$ne': True},
        "tipo": "Sesión Docente"
    }
    
    eventos, total_eventos, total_paginas = paginate_events(
        get_collection_eventos(),
        filtro, 
        page, 
        eventos_por_pagina,
        sort_field="fecha_inicio",
        sort_order=-1
    )
    
    collection_participantes = get_collection_participantes()
    
    for evento in eventos:
        es_organizador = collection_participantes.find_one({
            "codigo_evento": evento["codigo"],
            "cedula": str(current_user.cedula),
            "rol": "coorganizador"
        }) is not None 
        evento["es_organizador"] = es_organizador
    
    return render_template('mis_sesiones_docentes.html',
        eventos=eventos,
        total_eventos=total_eventos,
        page=page,
        total_paginas=total_paginas
    )


@events_bp.route('/eventos/abiertos')
@events_bp.route('/eventos/abiertos/page/<int:page>')
@login_required
def listar_eventos_abiertos(page=1):
    from app.events.services import (
        get_collection_eventos, 
        get_collection_participantes,
        get_collection_usuarios,
        paginate_events
    )
    
    eventos_por_pagina = 20
    filtro = {
        "registro_abierto": True,
        "estado_evento": "publicado"
    }
    
    eventos, total_eventos, total_paginas = paginate_events(
        get_collection_eventos(),
        filtro, 
        page, 
        eventos_por_pagina,
        sort_field="fecha_inicio",
        sort_order=-1
    )
    
    collection_participantes = get_collection_participantes()
    collection_usuarios = get_collection_usuarios()
    
    for evento in eventos:
        es_organizador = collection_participantes.find_one({
            "codigo_evento": evento["codigo"],
            "cedula": str(current_user.cedula),
            "rol": "coorganizador"
        }) is not None 
        evento["es_organizador"] = es_organizador
        
        if evento.get("autor"):
            evento["autor_info"] = collection_usuarios.find_one(
                {"_id": ObjectId(evento["autor"])},
                {"nombres": 1, "apellidos": 1, "foto": 1}
            )
    
    return render_template('eventos_abiertos.html',
        eventos=eventos,
        total_eventos=total_eventos,
        page=page,
        total_paginas=total_paginas
    )


@events_bp.route('/bases-de-datos')
@events_bp.route('/bases-de-datos/page/<int:page>')
@login_required
def db_eventos(page=1):
    from app.events.services import (
        get_collection_eventos,
        paginate_events
    )
    
    if current_user.rol != 'administrador':
        flash('No tienes permiso para acceder a esta página.', 'error')
        return redirect(url_for('home'))
    
    eventos_por_pagina = 50
    
    eventos, total_eventos, total_paginas = paginate_events(
        get_collection_eventos(),
        {}, 
        page, 
        eventos_por_pagina,
        sort_field="fecha_inicio",
        sort_order=-1
    )
    
    campos = set()
    for evento in eventos:
        campos.update(evento.keys())
    
    campos_importantes = ['codigo_evento', 'nombre', 'fecha_inicio', 'fecha_fin', 'estado_evento', 'unidad_ejecutora', 'tipo', 'modalidad', 'carga_horaria']
    campos.update(campos_importantes)
    
    campos = sorted(campos)
    
    return render_template('bd.html',
        eventos=eventos,
        campos=campos,
        page=page,
        total_paginas=total_paginas,
        total_eventos=total_eventos)