###
###
###  Este archivo contiene las rutas y funciones del sistema de mensajería
###  interna del tablero, incluyendo listas de distribución dinámicas
###  basadas en región y unidad ejecutora.
###
###  - Bandeja de entrada / enviados
###  - Redacción individual o difusión "a todos" (solo admin/denadoi)
###  - Hilos de respuesta
###  - Adjuntos (pdf, imágenes, ppt, pptx)
###  - Listas de distribución: globales (las crea el administrador,
###    las consume denadoi) y personales (privadas de su creador)
###
###
from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, send_from_directory, jsonify, abort, current_app)
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId
from datetime import datetime
import os
import uuid

from app import (
    collection_usuarios,
    collection_mensajes,
    collection_listas_mensajes,
)
from app.logs import log_event
from app.helpers import allowed_file
from app.auth.services import roles_required, UserRole
from app.unidades_data import REGION_LABEL, CSS_A_REGION

mensajeria_bp = Blueprint('mensajeria', __name__)

# Mismos roles con acceso al tablero
ROLES_TABLERO = [
    UserRole.COORDINADOR_DEPARTAMENTAL.value,
    UserRole.COORDINADOR_LOCAL.value,
    UserRole.COORDINADOR_REGIONAL.value,
    UserRole.COORDINADOR_NACIONAL.value,
    UserRole.SUBDIRECTOR_DOCENCIA.value,
    UserRole.COORDINADOR_ADMINISTRATIVO.value,
    UserRole.DENADOI.value,
    UserRole.SIMULACION.value,
    UserRole.ADMINISTRADOR.value,
]

# Roles que pueden enviar difusiones "a todos" y usar/crear listas de distribución
ROLES_LISTAS = [UserRole.ADMINISTRADOR.value, UserRole.DENADOI.value]

PAGE_SIZE = 20


###
### Helpers de permisos y datos
###

def _puede_usar_listas(usuario):
    """True si el usuario puede usar/crear listas de distribución."""
    return usuario.rol in ROLES_LISTAS


def _nombre_usuario(doc):
    return f"{doc.get('nombres', '')} {doc.get('apellidos', '')}".strip()


def _region_label(codigo):
    return REGION_LABEL.get(codigo, codigo)


def _destinatarios_visibles(usuario):
    """Usuarios internos activos a los que se puede escribir (excluye al propio usuario)."""
    query = {
        "rol": {"$in": ROLES_TABLERO},
        "activo": {"$ne": False},
        "_id": {"$ne": ObjectId(usuario.id)},
    }
    return list(collection_usuarios.find(
        query,
        {"nombres": 1, "apellidos": 1, "email": 1, "rol": 1,
         "region": 1, "unidad_ejecutora": 1}
    ).sort([("nombres", 1), ("apellidos", 1)]))


def _resolver_lista(lista_doc):
    """Resuelve una lista de distribución a usuarios activos.

    Devuelve (usuarios, criterio_vacio).
    """
    criterio = lista_doc.get('criterio') or {}
    regiones = [r for r in (criterio.get('regiones') or []) if r]
    unidades = [u for u in (criterio.get('unidades') or []) if u]

    condiciones = []
    if regiones:
        condiciones.append({"region": {"$in": regiones}})
    if unidades:
        condiciones.append({"unidad_ejecutora": {"$in": unidades}})

    if not condiciones:
        return [], True

    usuarios = list(collection_usuarios.find(
        {"activo": {"$ne": False}, "$or": condiciones},
        {"nombres": 1, "apellidos": 1, "email": 1}
    ))
    return usuarios, False


def _lista_autorizada(id_lista, usuario_actual):
    """Obtiene una lista si existe y el usuario puede consumirla.

    - globales: solo admin/denadoi
    - personales: solo su creador
    Devuelve None si no existe o no está autorizada.
    """
    try:
        oid = ObjectId(id_lista)
    except Exception:
        return None
    lista = collection_listas_mensajes.find_one({"_id": oid})
    if not lista:
        return None
    if lista.get('tipo') == 'global':
        if not _puede_usar_listas(usuario_actual):
            return None
    else:
        if str(lista.get('creador_id')) != usuario_actual.id:
            return None
    return lista


def _resolver_listas(ids_listas, usuario_actual):
    """Resuelve varias listas autorizadas a destinatarios únicos.

    Devuelve (ids_destinatarios, nombres_listas_usadas).
    """
    ids_validos = []
    nombres = []
    for id_lista in ids_listas or []:
        lista = _lista_autorizada(id_lista, usuario_actual)
        if not lista or id_lista in ids_validos:
            continue
        usuarios, criterio_vacio = _resolver_lista(lista)
        if criterio_vacio:
            continue
        ids_validos.append(id_lista)
        nombres.append(lista.get('nombre', ''))

    destinatarios = set()
    for oid in [ObjectId(i) for i in ids_validos]:
        lista = collection_listas_mensajes.find_one({"_id": oid})
        usuarios, _ = _resolver_lista(lista)
        for u in usuarios:
            destinatarios.add(str(u['_id']))
    return list(destinatarios), nombres


def _carpeta_mensaje(mensaje_id):
    return os.path.join(current_app.config['MENSAJES_FOLDER'], str(mensaje_id))


def _guardar_adjuntos(files, mensaje_id):
    """Guarda archivos adjuntos validados para un mensaje.

    Devuelve (adjuntos_meta, error). En caso de error elimina lo guardado.
    """
    max_archivo = current_app.config['MENSAJES_MAX_ARCHIVO_MB'] * 1024 * 1024
    max_adjuntos = current_app.config['MENSAJES_MAX_ADJUNTOS']
    extensiones = current_app.config['MENSAJES_EXTENSIONES']

    archivos = [f for f in files if f and f.filename]
    if len(archivos) > max_adjuntos:
        return [], f"Máximo {max_adjuntos} archivos adjuntos por mensaje."

    carpeta = _carpeta_mensaje(mensaje_id)
    adjuntos = []
    try:
        for f in archivos:
            if not allowed_file(f.filename, extensiones):
                return [], f"Tipo de archivo no permitido: {f.filename}"
            contenido = f.read()
            if len(contenido) > max_archivo:
                return [], (f"El archivo {f.filename} supera el límite de "
                            f"{current_app.config['MENSAJES_MAX_ARCHIVO_MB']} MB.")
            nombre_guardado = f"{uuid.uuid4().hex[:12]}_{secure_filename(f.filename)}"
            os.makedirs(carpeta, exist_ok=True)
            with open(os.path.join(carpeta, nombre_guardado), 'wb') as destino:
                destino.write(contenido)
            adjuntos.append({
                "nombre_original": secure_filename(f.filename),
                "nombre_guardado": nombre_guardado,
                "tamano": len(contenido),
            })
    except Exception:
        for a in adjuntos:
            ruta = os.path.join(carpeta, a['nombre_guardado'])
            if os.path.exists(ruta):
                os.remove(ruta)
        raise
    return adjuntos, None


def _acceso_mensaje(mensaje, usuario_actual):
    """True si el usuario puede ver el mensaje (remitente o destinatario)."""
    uid = usuario_actual.id
    return (str(mensaje.get('remitente_id')) == uid
            or uid in (mensaje.get('destinatarios') or [])
            or mensaje.get('es_global'))


def _hilo_del_mensaje(mensaje):
    """Devuelve la conversación completa: raíz + respuestas ordenadas."""
    raiz_id = mensaje.get('respuesta_a') or mensaje['_id']
    raiz = collection_mensajes.find_one({"_id": raiz_id}) if mensaje.get('respuesta_a') else mensaje
    if not raiz:
        raiz = mensaje
    respuestas = list(collection_mensajes.find(
        {"respuesta_a": raiz_id}
    ).sort("fecha", 1))
    return [raiz] + [r for r in respuestas if r['_id'] != raiz['_id']]


def _marcar_leido(mensaje):
    """Marca el mensaje como leído por el usuario actual si corresponde."""
    uid = current_user.id
    es_remitente = str(mensaje.get('remitente_id')) == uid
    es_destinatario = (uid in (mensaje.get('destinatarios') or [])
                       or mensaje.get('es_global'))
    if es_destinatario and not es_remitente and uid not in (mensaje.get('leido_por') or []):
        collection_mensajes.update_one(
            {"_id": mensaje['_id']},
            {"$addToSet": {"leido_por": uid}}
        )


def _enriquecer_con_remitente(mensajes):
    """Agrega remitente_info y estado de leído a una lista de mensajes."""
    cache = {}
    for m in mensajes:
        rid = str(m.get('remitente_id'))
        if rid not in cache:
            cache[rid] = collection_usuarios.find_one(
                {"_id": ObjectId(rid)},
                {"nombres": 1, "apellidos": 1, "foto": 1}
            )
        m['remitente_info'] = cache[rid]
        m['no_leido'] = (current_user.id not in (m.get('leido_por') or [])
                         and str(m.get('remitente_id')) != current_user.id)
        m['total_adjuntos'] = len(m.get('adjuntos') or [])
    return mensajes


def _contar_no_leidos():
    """Cantidad de mensajes sin leer para el usuario actual."""
    query = {
        "$or": [
            {"destinatarios": current_user.id},
            {"es_global": True},
        ],
        "remitente_id": {"$ne": current_user.id},
        "eliminado_para": {"$ne": current_user.id},
        "leido_por": {"$ne": current_user.id},
    }
    return collection_mensajes.count_documents(query)


###
### Bandeja de entrada
###

@mensajeria_bp.route('/tablero/mensajes')
@mensajeria_bp.route('/tablero/mensajes/page/<int:page>')
@roles_required(*ROLES_TABLERO)
def bandeja(page=1):
    caja = request.args.get('caja', 'recibidos')
    if caja not in ('recibidos', 'enviados'):
        caja = 'recibidos'

    if caja == 'enviados':
        query = {
            "remitente_id": current_user.id,
            "eliminado_para": {"$ne": current_user.id},
        }
    else:
        query = {
            "$or": [
                {"destinatarios": current_user.id},
                {"es_global": True},
            ],
            "remitente_id": {"$ne": current_user.id},
            "eliminado_para": {"$ne": current_user.id},
        }

    total = collection_mensajes.count_documents(query)
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(max(1, page), total_pages)

    mensajes = list(collection_mensajes.find(query)
                    .sort("fecha", -1)
                    .skip((page - 1) * PAGE_SIZE)
                    .limit(PAGE_SIZE))

    _enriquecer_con_remitente(mensajes)

    # Resumen de destinatarios para la vista enviados
    for m in mensajes:
        if m.get('es_global'):
            m['resumen_destinatarios'] = 'Todos los usuarios'
        else:
            n = len(m.get('destinatarios') or [])
            m['resumen_destinatarios'] = f"{n} destinatario{'s' if n != 1 else ''}"

    return render_template('mensajes.html',
        mensajes=mensajes,
        caja=caja,
        page=page,
        total_pages=total_pages,
        total=total,
        no_leidos=_contar_no_leidos(),
        puede_usar_listas=_puede_usar_listas(current_user),
        active_section='mensajeria',
    )


###
### Redacción y envío
###

@mensajeria_bp.route('/tablero/mensajes/nuevo', methods=['GET', 'POST'])
@roles_required(*ROLES_TABLERO)
def nuevo():
    if request.method == 'POST':
        asunto = (request.form.get('asunto') or '').strip()
        cuerpo = (request.form.get('cuerpo') or '').strip()
        difusion = request.form.get('difusion') == 'todos'
        ids_destinatarios = request.form.getlist('destinatarios')
        ids_listas = request.form.getlist('listas')

        if not asunto or not cuerpo:
            flash('El asunto y el mensaje son obligatorios.', 'error')
            return redirect(url_for('mensajeria.nuevo'))

        # Difusión "a todos": solo admin/denadoi
        if difusion and not _puede_usar_listas(current_user):
            abort(403)

        destinatarios = set()
        nombres_listas = []

        if not difusion:
            # Destinatarios individuales (validar que existan)
            for uid in ids_destinatarios:
                try:
                    if collection_usuarios.find_one(
                            {"_id": ObjectId(uid), "activo": {"$ne": False}}):
                        destinatarios.add(uid)
                except Exception:
                    continue

            # Listas de distribución (resolución server-side)
            ids_listas_resueltos, nombres_listas = _resolver_listas(ids_listas, current_user)
            destinatarios.update(ids_listas_resueltos)

        destinatarios.discard(current_user.id)

        if difusion:
            total_activos = collection_usuarios.count_documents(
                {"rol": {"$in": ROLES_TABLERO}, "activo": {"$ne": False},
                 "_id": {"$ne": ObjectId(current_user.id)}})
            if total_activos == 0:
                flash('No hay usuarios activos para enviar la difusión.', 'error')
                return redirect(url_for('mensajeria.nuevo'))
        elif not destinatarios:
            flash('Selecciona al menos un destinatario o lista válida.', 'error')
            return redirect(url_for('mensajeria.nuevo'))

        resultado = collection_mensajes.insert_one({
            "remitente_id": current_user.id,
            "remitente_nombre": _nombre_usuario(
                {"nombres": current_user.nombres, "apellidos": current_user.apellidos}),
            "destinatarios": sorted(destinatarios),
            "es_global": bool(difusion),
            "listas_usadas": nombres_listas,
            "asunto": asunto,
            "cuerpo": cuerpo,
            "adjuntos": [],
            "respuesta_a": None,
            "fecha": datetime.now(),
            "leido_por": [],
            "eliminado_para": [],
        })

        # Adjuntos
        archivos = request.files.getlist('adjuntos')
        if archivos:
            adjuntos, error = _guardar_adjuntos(archivos, resultado.inserted_id)
            if error:
                collection_mensajes.delete_one({"_id": resultado.inserted_id})
                flash(error, 'error')
                return redirect(url_for('mensajeria.nuevo'))
            if adjuntos:
                collection_mensajes.update_one(
                    {"_id": resultado.inserted_id},
                    {"$set": {"adjuntos": adjuntos}}
                )

        if difusion:
            log_event(f"Usuario [{current_user.email}] envió una difusión "
                      f"'{asunto}' a todos los usuarios del tablero.")
        else:
            detalle_listas = f" (listas: {', '.join(nombres_listas)})" if nombres_listas else ""
            log_event(f"Usuario [{current_user.email}] envió el mensaje '{asunto}' "
                      f"a {len(destinatarios)} destinatario(s){detalle_listas}.")
        flash('Mensaje enviado exitosamente.', 'success')
        return redirect(url_for('mensajeria.bandeja', caja='enviados'))

    para = request.args.get('para')
    resp = request.args.get('resp')

    destinatario_pre = None
    respuesta_pre = None
    if para:
        try:
            doc = collection_usuarios.find_one(
                {"_id": ObjectId(para)}, {"nombres": 1, "apellidos": 1})
        except Exception:
            pass
    if resp:
        try:
            m = collection_mensajes.find_one({"_id": ObjectId(resp)})
            if m and _acceso_mensaje(m, current_user):
                asunto_resp = m['asunto']
                if not asunto_resp.lower().startswith('re:'):
                    asunto_resp = f"RE: {asunto_resp}"
                respuesta_pre = {
                    "id": str(m['_id']),
                    "asunto": asunto_resp,
                    "cuerpo": m.get('cuerpo', ''),
                    "remitente_id": str(m.get('remitente_id')),
                }
        except Exception:
            pass

    usuarios = _destinatarios_visibles(current_user)
    for u in usuarios:
        u['nombre_completo'] = _nombre_usuario(u)

    def _serializar_lista(l):
        criterio = l.get('criterio') or {}
        return {
            "id": str(l['_id']),
            "nombre": l.get('nombre', ''),
            "tipo": l.get('tipo'),
            "regiones": [_region_label(r) for r in criterio.get('regiones', [])],
            "unidades": criterio.get('unidades', []),
        }

    listas_globales = []
    mis_listas = []
    if _puede_usar_listas(current_user):
        listas_globales = [
            _serializar_lista(l)
            for l in collection_listas_mensajes.find({"tipo": "global"}).sort("nombre", 1)
        ]
        propias = collection_listas_mensajes.find(
            {"tipo": "personal", "creador_id": current_user.id}).sort("nombre", 1)
        mis_listas = [_serializar_lista(l) for l in propias]

    unidades_por_region = {}
    try:
        from app.unidades_data import unidades_por_region as _upr
        unidades_por_region = _upr()
    except Exception:
        pass

    return render_template('mensaje_nuevo.html',
        usuarios=usuarios,
        destinatario_pre=destinatario_pre,
        respuesta_pre=respuesta_pre,
        difusion_permitida=_puede_usar_listas(current_user),
        puede_usar_listas=_puede_usar_listas(current_user),
        listas_globales=listas_globales,
        mis_listas=mis_listas,
        unidades_por_region=unidades_por_region,
        max_adjuntos=current_app.config['MENSAJES_MAX_ADJUNTOS'],
        max_archivo_mb=current_app.config['MENSAJES_MAX_ARCHIVO_MB'],
        active_section='mensajeria',
    )


###
### Ver mensaje (hilo completo)
###

@mensajeria_bp.route('/tablero/mensajes/<mensaje_id>')
@roles_required(*ROLES_TABLERO)
def ver(mensaje_id):
    try:
        mensaje = collection_mensajes.find_one({"_id": ObjectId(mensaje_id)})
    except Exception:
        abort(404)
    if not mensaje or not _acceso_mensaje(mensaje, current_user):
        abort(403)

    _marcar_leido(mensaje)

    hilo = _hilo_del_mensaje(mensaje)
    _enriquecer_con_remitente(hilo)

    # Nombres de destinatarios para mostrar en cada mensaje del hilo
    for m in hilo:
        nombres = []
        if m.get('es_global'):
            nombres = ['Todos los usuarios']
        else:
            docs = collection_usuarios.find(
                {"_id": {"$in": [ObjectId(d) for d in m.get('destinatarios', [])]}},
                {"nombres": 1, "apellidos": 1}
            )
            nombres = [_nombre_usuario(d) for d in docs]
        m['nombres_destinatarios'] = nombres

    return render_template('mensaje_ver.html',
        mensaje=mensaje,
        hilo=hilo,
        no_leidos=_contar_no_leidos(),
        active_section='mensajeria',
    )


###
### Responder a un mensaje
###

@mensajeria_bp.route('/tablero/mensajes/<mensaje_id>/responder', methods=['POST'])
@roles_required(*ROLES_TABLERO)
def responder(mensaje_id):
    try:
        original = collection_mensajes.find_one({"_id": ObjectId(mensaje_id)})
    except Exception:
        abort(404)
    if not original or not _acceso_mensaje(original, current_user):
        abort(403)

    cuerpo = (request.form.get('cuerpo') or '').strip()
    asunto_form = (request.form.get('asunto') or '').strip()
    if not cuerpo:
        flash('El mensaje de respuesta no puede estar vacío.', 'error')
        return redirect(url_for('mensajeria.ver', mensaje_id=mensaje_id))

    # La respuesta va dirigida al remitente del mensaje original
    remitente_original = str(original.get('remitente_id'))
    if remitente_original == current_user.id:
        # Responder a un mensaje propio: va a sus destinatarios originales
        destinatarios = [d for d in (original.get('destinatarios') or [])
                         if d != current_user.id]
    else:
        destinatarios = [remitente_original]

    if not destinatarios:
        flash('No hay destinatarios disponibles para responder.', 'error')
        return redirect(url_for('mensajeria.ver', mensaje_id=mensaje_id))

    asunto = asunto_form or original.get('asunto', '')
    if not asunto.lower().startswith('re:'):
        asunto = f"RE: {asunto}"

    raiz_id = original.get('respuesta_a') or original['_id']

    resultado = collection_mensajes.insert_one({
        "remitente_id": current_user.id,
        "remitente_nombre": _nombre_usuario(
            {"nombres": current_user.nombres, "apellidos": current_user.apellidos}),
        "destinatarios": destinatarios,
        "es_global": False,
        "listas_usadas": [],
        "asunto": asunto,
        "cuerpo": cuerpo,
        "adjuntos": [],
        "respuesta_a": raiz_id,
        "fecha": datetime.now(),
        "leido_por": [],
        "eliminado_para": [],
    })

    archivos = request.files.getlist('adjuntos')
    if archivos:
        adjuntos, error = _guardar_adjuntos(archivos, resultado.inserted_id)
        if error:
            collection_mensajes.delete_one({"_id": resultado.inserted_id})
            flash(error, 'error')
            return redirect(url_for('mensajeria.ver', mensaje_id=mensaje_id))
        if adjuntos:
            collection_mensajes.update_one(
                {"_id": resultado.inserted_id},
                {"$set": {"adjuntos": adjuntos}}
            )

    log_event(f"Usuario [{current_user.email}] respondió al mensaje "
              f"'{original.get('asunto')}' ({len(destinatarios)} destinatario(s)).")
    flash('Respuesta enviada exitosamente.', 'success')
    return redirect(url_for('mensajeria.ver', mensaje_id=str(raiz_id)))


###
### Eliminar (suave, por usuario)
###

@mensajeria_bp.route('/tablero/mensajes/<mensaje_id>/eliminar', methods=['POST'])
@roles_required(*ROLES_TABLERO)
def eliminar(mensaje_id):
    try:
        mensaje = collection_mensajes.find_one({"_id": ObjectId(mensaje_id)})
    except Exception:
        abort(404)
    if not mensaje or not _acceso_mensaje(mensaje, current_user):
        abort(403)

    collection_mensajes.update_one(
        {"_id": mensaje['_id']},
        {"$addToSet": {"eliminado_para": current_user.id}}
    )
    log_event(f"Usuario [{current_user.email}] eliminó de su bandeja "
              f"el mensaje '{mensaje.get('asunto')}'.")
    flash('Mensaje eliminado.', 'success')
    return redirect(url_for('mensajeria.bandeja'))


###
### Descarga segura de adjuntos
###

@mensajeria_bp.route('/tablero/mensajes/<mensaje_id>/adjuntos/<int:indice>')
@roles_required(*ROLES_TABLERO)
def descargar_adjunto(mensaje_id, indice):
    try:
        mensaje = collection_mensajes.find_one({"_id": ObjectId(mensaje_id)})
    except Exception:
        abort(404)
    if not mensaje or not _acceso_mensaje(mensaje, current_user):
        abort(403)

    adjuntos = mensaje.get('adjuntos') or []
    if indice < 0 or indice >= len(adjuntos):
        abort(404)

    adjunto = adjuntos[indice]
    carpeta = _carpeta_mensaje(mensaje['_id'])
    ruta = os.path.join(carpeta, adjunto['nombre_guardado'])
    if not os.path.exists(ruta):
        abort(404)

    return send_from_directory(
        carpeta,
        adjunto['nombre_guardado'],
        as_attachment=True,
        download_name=adjunto['nombre_original'],
    )


###
### API: contador de no leídos para el badge del encabezado
###

@mensajeria_bp.route('/tablero/mensajes/api/no-leidos')
@login_required
def api_no_leidos():
    if current_user.rol not in ROLES_TABLERO:
        return jsonify({"count": 0})
    return jsonify({"count": _contar_no_leidos()})


###
### Gestión de listas de distribución (solo admin/denadoi)
###

def _listas_para_usuario():
    """Listas visibles para el usuario actual, con total resuelto."""
    if _puede_usar_listas(current_user):
        globales = collection_listas_mensajes.find({"tipo": "global"}).sort("nombre", 1)
    else:
        globales = []
    propias = collection_listas_mensajes.find(
        {"tipo": "personal", "creador_id": current_user.id}).sort("nombre", 1)

    def serializar(l):
        usuarios, criterio_vacio = _resolver_lista(l)
        criterio = l.get('criterio') or {}
        return {
            "id": str(l['_id']),
            "nombre": l.get('nombre', ''),
            "tipo": l.get('tipo'),
            "regiones_codigos": criterio.get('regiones', []),
            "regiones": [_region_label(r) for r in criterio.get('regiones', [])],
            "unidades": criterio.get('unidades', []),
            "total_usuarios": len(usuarios),
            "criterio_vacio": criterio_vacio,
        }

    return [serializar(l) for l in globales], [serializar(l) for l in propias]


@mensajeria_bp.route('/tablero/mensajes/listas')
@roles_required(*ROLES_LISTAS)
def listas():
    globales, propias = _listas_para_usuario()
    regiones_disponibles = [
        {"codigo": css, "label": REGION_LABEL.get(slug, slug)}
        for slug, css in sorted(CSS_A_REGION.items(),
                                key=lambda x: REGION_LABEL.get(x[1], x[1]))
        if css != 'css00'
    ]
    try:
        from app.unidades_data import unidades_por_region as _upr
        unidades_por_region = _upr()
    except Exception:
        unidades_por_region = {}

    return render_template('mensajes_listas.html',
        listas_globales=globales,
        mis_listas=propias,
        es_admin=current_user.is_admin(),
        regiones_disponibles=regiones_disponibles,
        unidades_por_region=unidades_por_region,
        region_label=REGION_LABEL,
        no_leidos=_contar_no_leidos(),
        active_section='mensajeria',
    )


@mensajeria_bp.route('/tablero/mensajes/listas/nueva', methods=['POST'])
@roles_required(*ROLES_LISTAS)
def nueva_lista():
    nombre = (request.form.get('nombre') or '').strip()
    tipo = request.form.get('tipo', 'personal')
    regiones = request.form.getlist('regiones')
    unidades = [u for u in request.form.getlist('unidades') if u]

    if not nombre:
        flash('El nombre de la lista es obligatorio.', 'error')
        return redirect(url_for('mensajeria.listas'))

    # Solo administrador puede crear listas globales
    if tipo not in ('global', 'personal'):
        tipo = 'personal'
    if tipo == 'global' and not current_user.is_admin():
        abort(403)

    # Las personales siempre pertenecen al creador
    creador_id = current_user.id

    if not regiones and not unidades:
        flash('Selecciona al menos una región o unidad ejecutora.', 'error')
        return redirect(url_for('mensajeria.listas'))

    existente = collection_listas_mensajes.find_one({
        "nombre": nombre, "tipo": tipo, "creador_id": creador_id})
    if existente:
        flash(f"Ya existe una lista llamada '{nombre}'.", 'error')
        return redirect(url_for('mensajeria.listas'))

    collection_listas_mensajes.insert_one({
        "nombre": nombre,
        "tipo": tipo,
        "creador_id": creador_id,
        "criterio": {"regiones": regiones, "unidades": unidades},
        "fecha_creacion": datetime.now(),
        "activa": True,
    })
    log_event(f"Usuario [{current_user.email}] creó la lista de distribución "
              f"'{nombre}' ({tipo}).")
    flash('Lista creada exitosamente.', 'success')
    return redirect(url_for('mensajeria.listas'))


@mensajeria_bp.route('/tablero/mensajes/listas/<lista_id>/eliminar', methods=['POST'])
@roles_required(*ROLES_LISTAS)
def eliminar_lista(lista_id):
    try:
        lista = collection_listas_mensajes.find_one({"_id": ObjectId(lista_id)})
    except Exception:
        abort(404)
    if not lista:
        abort(404)

    # Globales: solo administrador. Personales: solo su creador.
    if lista.get('tipo') == 'global':
        if not current_user.is_admin():
            abort(403)
    else:
        if str(lista.get('creador_id')) != current_user.id:
            abort(403)

    collection_listas_mensajes.delete_one({"_id": lista['_id']})
    log_event(f"Usuario [{current_user.email}] eliminó la lista de distribución "
              f"'{lista.get('nombre')}' ({lista.get('tipo')}).")
    flash('Lista eliminada.', 'success')
    return redirect(url_for('mensajeria.listas'))


@mensajeria_bp.route('/tablero/mensajes/api/listas/<lista_id>/preview')
@roles_required(*ROLES_LISTAS)
def api_preview_lista(lista_id):
    lista = _lista_autorizada(lista_id, current_user)
    if not lista:
        return jsonify({"error": "Lista no encontrada o sin acceso."}), 404

    usuarios, criterio_vacio = _resolver_lista(lista)
    muestra = [_nombre_usuario(u) for u in usuarios[:10]]
    return jsonify({
        "id": str(lista['_id']),
        "nombre": lista.get('nombre', ''),
        "total": len(usuarios),
        "muestra": muestra,
        "criterio_vacio": criterio_vacio,
    })
