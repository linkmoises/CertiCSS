import os
import secrets
from datetime import datetime
from bson.objectid import ObjectId
from flask import abort, render_template, request, redirect, url_for, flash, send_from_directory
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from app import db, collection_participantes
from app.auth_decorators import generate_token, verify_token
from app.helpers import allowed_file
from app.logs import log_event
from app.certificados_externos import certificados_externos_bp, collection_certificados_externos

UPLOAD_FOLDER = 'static/uploads/certificados_externos'
ALLOWED_EXTENSIONS = {'pdf'}
ROLES_PERMITIDOS = ['administrador', 'denadoi']

# Roles disponibles (coinciden con los del sistema)
ROLES_DISPONIBLES = [
    ('participante', 'Participante'),
    ('ponente', 'Ponente'),
    ('organizador', 'Organizador'),
    ('coorganizador', 'Coorganizador'),
    ('jurado_poster', 'Jurado Poster'),
    ('presentador_poster', 'Presentador Poster'),
]


def _get_upload_path():
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    return UPLOAD_FOLDER


def _fmt_date(d):
    if isinstance(d, datetime):
        return d.strftime('%d/%m/%Y')
    return str(d) if d else '—'


def _fmt_date_input(d):
    if isinstance(d, datetime):
        return d.strftime('%Y-%m-%d')
    return ''


### PÚBLICAS ###

@certificados_externos_bp.route('/certificado-externo/nuevo', methods=['GET', 'POST'])
def nuevo_externo():
    if request.method == 'GET':
        cedula = request.args.get('cedula', '').strip()
        token = request.args.get('token', '').strip()

        if not cedula or not token or not verify_token(cedula, token):
            flash('Enlace inválido o expirado. Busque su cédula nuevamente.', 'error')
            return redirect(url_for('buscar_certificados'))

        participante = collection_participantes.find_one({"cedula": cedula})
        if not participante:
            flash('Cédula no encontrada en el sistema.', 'error')
            return redirect(url_for('buscar_certificados'))

        return render_template('certificado_externo_nuevo.html',
                               cedula=cedula, token=token,
                               nombres=participante.get('nombres', ''),
                               apellidos=participante.get('apellidos', ''))

    # POST
    cedula = request.form.get('cedula', '').strip()
    token = request.form.get('token', '').strip()
    titulo = request.form.get('titulo', '').strip()
    fecha_inicio_str = request.form.get('fecha_inicio', '').strip()
    fecha_fin_str = request.form.get('fecha_fin', '').strip()
    horas_str = request.form.get('horas', '').strip()
    rol = request.form.get('rol', 'participante').strip()

    if not cedula or not token or not verify_token(cedula, token):
        flash('Sesión inválida o expirada. Busque su cédula nuevamente.', 'error')
        return redirect(url_for('buscar_certificados'))

    errores = []
    if not titulo:
        errores.append('El título del certificado es requerido.')
    if not fecha_inicio_str:
        errores.append('La fecha de inicio es requerida.')
    if not fecha_fin_str:
        errores.append('La fecha de fin es requerida.')
    if not horas_str:
        errores.append('La cantidad de horas es requerida.')

    fecha_inicio = None
    if fecha_inicio_str:
        try:
            fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%d')
        except ValueError:
            errores.append('Formato de fecha de inicio inválido.')

    fecha_fin = None
    if fecha_fin_str:
        try:
            fecha_fin = datetime.strptime(fecha_fin_str, '%Y-%m-%d')
        except ValueError:
            errores.append('Formato de fecha de fin inválido.')

    if fecha_inicio and fecha_fin and fecha_inicio > fecha_fin:
        errores.append('La fecha de fin debe ser posterior o igual a la fecha de inicio.')

    horas = None
    if horas_str:
        try:
            horas = float(horas_str)
            if horas <= 0 or horas > 999:
                errores.append('Las horas deben ser un número positivo (máx. 999).')
        except ValueError:
            errores.append('Formato de horas inválido.')

    if 'archivo' not in request.files:
        errores.append('Debe adjuntar el certificado en formato PDF.')
    else:
        file = request.files['archivo']
        if file.filename == '':
            errores.append('Debe seleccionar un archivo.')
        elif not allowed_file(file.filename, ALLOWED_EXTENSIONS):
            errores.append('Solo se permiten archivos PDF.')

    if errores:
        participante = collection_participantes.find_one({"cedula": cedula})
        for e in errores:
            flash(e, 'error')
        return render_template('certificado_externo_nuevo.html',
                               cedula=cedula, token=token,
                               nombres=participante.get('nombres', '') if participante else '',
                               apellidos=participante.get('apellidos', '') if participante else '',
                               titulo=titulo,
                               fecha_inicio=fecha_inicio_str,
                               fecha_fin=fecha_fin_str,
                               horas=horas_str)

    file = request.files['archivo']
    original_filename = secure_filename(file.filename)
    unique_id = secrets.token_hex(12)
    stored_filename = f"{unique_id}_{original_filename}"

    upload_path = _get_upload_path()
    file_path = os.path.join(upload_path, stored_filename)
    file.save(file_path)

    doc = {
        "cedula": cedula, "nombres": '', "apellidos": '',
        "titulo": titulo,
        "fecha_inicio": fecha_inicio,
        "fecha_fin": fecha_fin,
        "horas": horas,
        "rol": rol,
        "archivo": stored_filename,
        "archivo_original": original_filename,
        "status": "revision",
        "validado_por": None, "validado_en": None,
        "rechazado_por": None, "motivo_rechazo": None,
        "created_at": datetime.now(), "updated_at": datetime.now(),
    }

    participante = collection_participantes.find_one({"cedula": cedula})
    if participante:
        doc["nombres"] = participante.get('nombres', '')
        doc["apellidos"] = participante.get('apellidos', '')

    collection_certificados_externos.insert_one(doc)

    log_event(f"Certificado externo subido por cédula {cedula}: {titulo} ({horas}h, rol: {rol})")
    flash('Certificado externo subido exitosamente. Quedará en revisión por el equipo de DENADOI.', 'success')
    return redirect(url_for('buscar_certificados', cedula=cedula, token=token))


@certificados_externos_bp.route('/certificado-externo/<id>/ver')
def ver_externo(id):
    cedula = request.args.get('cedula', '').strip()
    token = request.args.get('token', '').strip()

    if not cedula or not token or not verify_token(cedula, token):
        abort(401)

    cert = collection_certificados_externos.find_one({
        "_id": ObjectId(id),
        "cedula": cedula,
        "status": "aprobado"
    })
    if not cert or not cert.get('archivo'):
        abort(404)

    return send_from_directory(
        os.path.abspath(UPLOAD_FOLDER),
        cert['archivo'],
        download_name=cert.get('archivo_original', 'certificado.pdf'),
        as_attachment=False
    )


### INTERNAS (requieren autenticación) ###

@certificados_externos_bp.route('/tablero/certificados-externos')
@login_required
def listar_pendientes():
    if current_user.rol not in ROLES_PERMITIDOS:
        flash('No tiene permisos para acceder a esta sección.', 'error')
        return redirect(url_for('tablero_coordinadores'))

    pendientes = list(collection_certificados_externos.find(
        {"status": "revision"}
    ).sort("created_at", -1))

    for p in pendientes:
        fi = p.get('fecha_inicio') or p.get('fecha')
        ff = p.get('fecha_fin') or p.get('fecha')
        p['fecha_str'] = _fmt_date(fi)
        p['fecha_fin_str'] = _fmt_date(ff)
        if isinstance(p.get('created_at'), datetime):
            p['creado_str'] = p['created_at'].strftime('%d/%m/%Y %H:%M')

    return render_template('certificado_externo_listar.html',
                           pendientes=pendientes,
                           active_section='certificados_externos')


@certificados_externos_bp.route('/tablero/certificados-externos/completados')
@login_required
def listar_completados():
    if current_user.rol not in ROLES_PERMITIDOS:
        flash('No tiene permisos para acceder a esta sección.', 'error')
        return redirect(url_for('tablero_coordinadores'))

    aprobados = list(collection_certificados_externos.find(
        {"status": "aprobado"}
    ).sort("validado_en", -1))

    rechazados = list(collection_certificados_externos.find(
        {"status": "rechazado"}
    ).sort("updated_at", -1))

    for item in aprobados + rechazados:
        fi = item.get('fecha_inicio') or item.get('fecha')
        ff = item.get('fecha_fin') or item.get('fecha')
        item['fecha_str'] = _fmt_date(fi)
        item['fecha_fin_str'] = _fmt_date(ff)
        if isinstance(item.get('validado_en'), datetime):
            item['validado_str'] = item['validado_en'].strftime('%d/%m/%Y %H:%M')
        elif isinstance(item.get('updated_at'), datetime):
            item['validado_str'] = item['updated_at'].strftime('%d/%m/%Y %H:%M')

    return render_template('certificado_externo_listar.html',
                           aprobados=aprobados, rechazados=rechazados,
                           active_section='certificados_externos')


@certificados_externos_bp.route('/tablero/certificados-externos/<id>')
@login_required
def detalle(id):
    if current_user.rol not in ROLES_PERMITIDOS:
        flash('No tiene permisos para acceder a esta sección.', 'error')
        return redirect(url_for('tablero_coordinadores'))

    cert = collection_certificados_externos.find_one({"_id": ObjectId(id)})
    if not cert:
        flash('Certificado externo no encontrado.', 'error')
        return redirect(url_for('certificados_externos.listar_pendientes'))

    fi = cert.get('fecha_inicio') or cert.get('fecha')
    ff = cert.get('fecha_fin') or cert.get('fecha')
    cert['fecha_inicio_str'] = _fmt_date(fi)
    cert['fecha_fin_str'] = _fmt_date(ff)
    cert['fecha_inicio_input'] = _fmt_date_input(fi)
    cert['fecha_fin_input'] = _fmt_date_input(ff)

    # Certificados existentes de la misma persona (para detectar duplicados)
    existentes = list(collection_certificados_externos.find({
        "cedula": cert['cedula'],
        "_id": {"$ne": ObjectId(id)}
    }).sort("created_at", -1))
    for e in existentes:
        fi2 = e.get('fecha_inicio') or e.get('fecha')
        ff2 = e.get('fecha_fin') or e.get('fecha')
        e['fecha_str'] = _fmt_date(fi2)
        e['fecha_fin_str'] = _fmt_date(ff2)

    return render_template('certificado_externo_detalle.html',
                           cert=cert, roles=ROLES_DISPONIBLES,
                           existentes=existentes,
                           active_section='certificados_externos')


@certificados_externos_bp.route('/tablero/certificados-externos/<id>/aprobar', methods=['POST'])
@login_required
def aprobar(id):
    if current_user.rol not in ROLES_PERMITIDOS:
        flash('No tiene permisos para realizar esta acción.', 'error')
        return redirect(url_for('tablero_coordinadores'))

    cert = collection_certificados_externos.find_one({"_id": ObjectId(id)})
    if not cert:
        flash('Certificado externo no encontrado.', 'error')
        return redirect(url_for('certificados_externos.listar_pendientes'))

    update = {
        "status": "aprobado",
        "validado_por": str(current_user.id),
        "validado_en": datetime.now(),
        "updated_at": datetime.now(),
    }

    fecha_inicio_str = request.form.get('fecha_inicio', '').strip()
    fecha_fin_str = request.form.get('fecha_fin', '').strip()
    horas_str = request.form.get('horas', '').strip()
    rol = request.form.get('rol', '').strip()

    if fecha_inicio_str:
        try:
            update["fecha_inicio"] = datetime.strptime(fecha_inicio_str, '%Y-%m-%d')
        except ValueError:
            flash('Formato de fecha de inicio inválido.', 'error')
            return redirect(url_for('certificados_externos.detalle', id=id))

    if fecha_fin_str:
        try:
            update["fecha_fin"] = datetime.strptime(fecha_fin_str, '%Y-%m-%d')
        except ValueError:
            flash('Formato de fecha de fin inválido.', 'error')
            return redirect(url_for('certificados_externos.detalle', id=id))

    if horas_str:
        try:
            h = float(horas_str)
            if h > 0:
                update["horas"] = h
        except ValueError:
            flash('Formato de horas inválido.', 'error')
            return redirect(url_for('certificados_externos.detalle', id=id))

    if rol and rol in [r[0] for r in ROLES_DISPONIBLES]:
        update["rol"] = rol

    collection_certificados_externos.update_one(
        {"_id": ObjectId(id)},
        {"$set": update}
    )

    log_event(f"Certificado externo APROBADO por [{current_user.email}]: {cert.get('titulo')} "
              f"(cédula: {cert.get('cedula')}, {update.get('horas', cert.get('horas'))}h, rol: {update.get('rol', cert.get('rol', 'participante'))})")
    flash('Certificado externo aprobado. Las horas se sumarán al total del participante.', 'success')
    return redirect(url_for('certificados_externos.listar_pendientes'))


@certificados_externos_bp.route('/tablero/certificados-externos/<id>/rechazar', methods=['POST'])
@login_required
def rechazar(id):
    if current_user.rol not in ROLES_PERMITIDOS:
        flash('No tiene permisos para realizar esta acción.', 'error')
        return redirect(url_for('tablero_coordinadores'))

    cert = collection_certificados_externos.find_one({"_id": ObjectId(id)})
    if not cert:
        flash('Certificado externo no encontrado.', 'error')
        return redirect(url_for('certificados_externos.listar_pendientes'))

    motivo = request.form.get('motivo', '').strip()
    if not motivo:
        flash('Debe indicar un motivo de rechazo.', 'error')
        return redirect(url_for('certificados_externos.detalle', id=id))

    collection_certificados_externos.update_one(
        {"_id": ObjectId(id)},
        {"$set": {
            "status": "rechazado",
            "rechazado_por": str(current_user.id),
            "motivo_rechazo": motivo,
            "updated_at": datetime.now(),
        }}
    )

    log_event(f"Certificado externo RECHAZADO por [{current_user.email}]: {cert.get('titulo')} "
              f"(cédula: {cert.get('cedula')}, motivo: {motivo})")
    flash('Certificado externo rechazado.', 'success')
    return redirect(url_for('certificados_externos.listar_pendientes'))


@certificados_externos_bp.route('/tablero/certificados-externos/<id>/archivo')
@login_required
def descargar_archivo(id):
    if current_user.rol not in ROLES_PERMITIDOS:
        abort(403)

    cert = collection_certificados_externos.find_one({"_id": ObjectId(id)})
    if not cert or not cert.get('archivo'):
        abort(404)

    return send_from_directory(
        os.path.abspath(UPLOAD_FOLDER),
        cert['archivo'],
        download_name=cert.get('archivo_original', 'certificado.pdf'),
        as_attachment=True
    )


@certificados_externos_bp.route('/tablero/certificados-externos/<id>/reabrir', methods=['POST'])
@login_required
def reabrir(id):
    if current_user.rol not in ROLES_PERMITIDOS:
        flash('No tiene permisos para realizar esta acción.', 'error')
        return redirect(url_for('tablero_coordinadores'))

    cert = collection_certificados_externos.find_one({"_id": ObjectId(id)})
    if not cert:
        flash('Certificado externo no encontrado.', 'error')
        return redirect(url_for('certificados_externos.listar_pendientes'))

    update = {
        "status": "revision",
        "validado_por": None,
        "validado_en": None,
        "rechazado_por": None,
        "motivo_rechazo": None,
        "updated_at": datetime.now(),
    }

    fecha_inicio_str = request.form.get('fecha_inicio', '').strip()
    fecha_fin_str = request.form.get('fecha_fin', '').strip()
    horas_str = request.form.get('horas', '').strip()
    rol = request.form.get('rol', '').strip()

    if fecha_inicio_str:
        try:
            update["fecha_inicio"] = datetime.strptime(fecha_inicio_str, '%Y-%m-%d')
        except ValueError:
            flash('Formato de fecha de inicio inválido.', 'error')
            return redirect(url_for('certificados_externos.detalle', id=id))

    if fecha_fin_str:
        try:
            update["fecha_fin"] = datetime.strptime(fecha_fin_str, '%Y-%m-%d')
        except ValueError:
            flash('Formato de fecha de fin inválido.', 'error')
            return redirect(url_for('certificados_externos.detalle', id=id))

    if horas_str:
        try:
            h = float(horas_str)
            if h > 0:
                update["horas"] = h
        except ValueError:
            flash('Formato de horas inválido.', 'error')
            return redirect(url_for('certificados_externos.detalle', id=id))

    if rol and rol in [r[0] for r in ROLES_DISPONIBLES]:
        update["rol"] = rol

    collection_certificados_externos.update_one(
        {"_id": ObjectId(id)},
        {"$set": update}
    )

    log_event(f"Certificado externo REABIERTO por [{current_user.email}]: {cert.get('titulo')} "
              f"(cédula: {cert.get('cedula')})")
    flash('Certificado externo reabierto para revisión.', 'success')
    return redirect(url_for('certificados_externos.listar_pendientes'))


@certificados_externos_bp.route('/tablero/certificados-externos/<id>/eliminar', methods=['POST'])
@login_required
def eliminar(id):
    if current_user.rol not in ROLES_PERMITIDOS:
        flash('No tiene permisos para realizar esta acción.', 'error')
        return redirect(url_for('tablero_coordinadores'))

    cert = collection_certificados_externos.find_one({"_id": ObjectId(id)})
    if not cert:
        flash('Certificado externo no encontrado.', 'error')
        return redirect(url_for('certificados_externos.listar_pendientes'))

    # Eliminar archivo físico
    if cert.get('archivo'):
        file_path = os.path.join(_get_upload_path(), cert['archivo'])
        if os.path.exists(file_path):
            os.remove(file_path)

    collection_certificados_externos.delete_one({"_id": ObjectId(id)})

    log_event(f"Certificado externo ELIMINADO por [{current_user.email}]: {cert.get('titulo')} "
              f"(cédula: {cert.get('cedula')}, {cert.get('horas', 0)}h)")
    flash('Certificado externo eliminado permanentemente.', 'success')
    return redirect(url_for('certificados_externos.listar_completados'))
