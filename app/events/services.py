from datetime import datetime, timedelta
from typing import Optional, Tuple, List, Dict, Any
import re


_collection_eventos = None
_collection_participantes = None
_collection_usuarios = None
_collection_preregistro = None


def init_events_services(collection_eventos, collection_participantes, collection_usuarios, collection_preregistro):
    global _collection_eventos, _collection_participantes, _collection_usuarios, _collection_preregistro
    _collection_eventos = collection_eventos
    _collection_participantes = collection_participantes
    _collection_usuarios = collection_usuarios
    _collection_preregistro = collection_preregistro


def get_collection_eventos():
    return _collection_eventos


def get_collection_participantes():
    return _collection_participantes


def get_collection_usuarios():
    return _collection_usuarios


def get_collection_preregistro():
    return _collection_preregistro


def parse_event_date(date_value):
    from app.template_selection import parse_event_date as parse_date
    return parse_date(date_value)


def generate_nanoid(cedula, codigo_evento, titulo_ponencia=None):
    from app.helpers import generate_nanoid as _generate_nanoid
    return _generate_nanoid(cedula, codigo_evento, titulo_ponencia)


def obtener_codigo_unico(collection_eventos):
    from app.helpers import obtener_codigo_unico as _obtener_codigo_unico
    return _obtener_codigo_unico(collection_eventos)


def log_event(message):
    from app.logs import log_event as _log_event
    return _log_event(message)


def cargar_funcionarios_css(db):
    from app import cargar_funcionarios_css as _cargar_funcionarios_css
    return _cargar_funcionarios_css()


def format_event_stats(collection_eventos, collection_participantes, collection_usuarios, current_user, exclude_open_registration=True):
    inicio_hoy = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    fin_hoy = inicio_hoy.replace(hour=23, minute=59, second=59, microsecond=999999)
    
    query_filter = {}
    if exclude_open_registration:
        query_filter['registro_abierto'] = {'$ne': True}
    
    total_eventos = collection_eventos.count_documents(query_filter)
    
    eventos_cursor = collection_eventos.find({
        "$or": [
            {"fecha_inicio": {"$gte": inicio_hoy}},
            {
                "fecha_inicio": {"$lte": fin_hoy},
                "fecha_fin": {"$gte": inicio_hoy}
            }
        ],
        "estado_evento": {"$ne": "borrador"},
        **query_filter
    }).sort("fecha_inicio", 1).limit(5)

    eventos = list(eventos_cursor)

    for evento in eventos:
        from bson.objectid import ObjectId
        es_organizador = collection_participantes.find_one({
            "codigo_evento": evento.get("codigo"),
            "cedula": str(current_user.cedula),
            "rol": "coorganizador",
        }) is not None or (str(current_user.id) == str(evento.get("autor")))
        evento["es_organizador"] = es_organizador
        
        if evento.get("autor"):
            evento["autor_info"] = collection_usuarios.find_one(
                {"_id": ObjectId(evento["autor"])},
                {"nombres": 1, "apellidos": 1, "foto": 1}
            )

    return {
        'total_eventos': total_eventos,
        'eventos': eventos,
        'num_eventos': len(eventos)
    }


def get_event_dates(evento):
    fecha_inicio = parse_event_date(evento.get('fecha_inicio'))
    fecha_fin = parse_event_date(evento.get('fecha_fin'))
    
    if not fecha_inicio:
        return []
    
    if not fecha_fin or fecha_inicio.date() == fecha_fin.date():
        return [fecha_inicio.strftime('%Y-%m-%d')]
    
    dates = []
    current_date = fecha_inicio
    while current_date.date() <= fecha_fin.date():
        dates.append(current_date.strftime('%Y-%m-%d'))
        current_date += timedelta(days=1)
    
    return dates


def extract_extemporaneous_form_data(request_form):
    return {
        'nombres': request_form.get('nombres', '').strip(),
        'apellidos': request_form.get('apellidos', '').strip(),
        'cedula': request_form.get('cedula', '').strip(),
        'perfil_profesional': request_form.get('perfil_profesional', '').strip(),
        'region': request_form.get('region', '').strip(),
        'unidad': request_form.get('unidad', '').strip(),
        'fecha_evento': request_form.get('fecha_evento', '').strip(),
        'registro_extemporaneo': request_form.get('registro_extemporaneo') == 'true'
    }


def validate_extemporaneous_form_data(form_data, evento):
    errors = []
    
    required_fields = ['nombres', 'apellidos', 'cedula', 'perfil_profesional', 'region', 'unidad']
    field_names = {
        'nombres': 'Nombres',
        'apellidos': 'Apellidos', 
        'cedula': 'Cédula',
        'perfil_profesional': 'Perfil profesional',
        'region': 'Región',
        'unidad': 'Unidad'
    }
    
    for field in required_fields:
        if not form_data.get(field):
            errors.append(f'{field_names[field]} es requerido.')
    
    if form_data.get('cedula'):
        cedula = form_data['cedula']
        cedula_pattern = r'^(PE|E|N|\d{1,2}(AV|PI)?)-\d{1,4}-\d{1,6}$|^[A-Z]{2}\d{6,20}$'
        if not re.match(cedula_pattern, cedula):
            errors.append('Formato de cédula inválido.')
    
    if evento:
        fecha_inicio = parse_event_date(evento.get('fecha_inicio'))
        fecha_fin = parse_event_date(evento.get('fecha_fin'))
        
        if fecha_inicio and fecha_fin and fecha_inicio.date() != fecha_fin.date():
            if not form_data.get('fecha_evento'):
                errors.append('Debe seleccionar una fecha para este evento de múltiples días.')
            else:
                try:
                    selected_date = datetime.strptime(form_data['fecha_evento'], '%Y-%m-%d').date()
                    if selected_date < fecha_inicio.date() or selected_date > fecha_fin.date():
                        errors.append('La fecha seleccionada no está dentro del rango del evento.')
                except ValueError:
                    errors.append('Formato de fecha inválido.')
    
    return len(errors) == 0, errors


def check_duplicate_extemporaneous_registration(cedula, codigo_evento, collection_participantes, fecha_evento=None):
    if not fecha_evento:
        fecha_evento = datetime.now().strftime('%Y-%m-%d')
    
    indice_registro = datetime.strptime(fecha_evento, '%Y-%m-%d').strftime('%Y%m%d')
    
    existing_registration = collection_participantes.find_one({
        "cedula": cedula,
        "codigo_evento": codigo_evento,
        "rol": "participante",
        "$or": [
            {"fecha_evento": fecha_evento},
            {"indice_registro": indice_registro}
        ]
    })
    
    if existing_registration:
        existing_fecha = existing_registration.get('fecha_evento')
        existing_indice = existing_registration.get('indice_registro')
        
        is_same_date = (
            existing_fecha == fecha_evento or 
            existing_indice == indice_registro
        )
        
        if is_same_date:
            return True, "El participante ya está registrado en este evento para la fecha seleccionada."
    
    return False, None


def check_user_can_edit_event(evento, current_user, collection_participantes):
    if current_user.rol == 'administrador':
        return True
    
    if current_user.rol == 'denadoi':
        return True
    
    if str(current_user.id) == str(evento.get('autor')):
        return True
    
    es_organizador = collection_participantes.find_one({
        "codigo_evento": evento.get('codigo'),
        "cedula": str(current_user.cedula),
        "rol": {"$in": ["organizador", "coorganizador"]}
    }) is not None
    
    return es_organizador


def check_user_can_register_extemporaneo(evento, current_user, collection_participantes):
    es_organizador = collection_participantes.find_one({
        "codigo_evento": evento.get('codigo'),
        "cedula": current_user.cedula,
        "rol": {"$in": ["organizador", "coorganizador"]}
    }) is not None
    
    puede_registrar = (
        current_user.rol == 'administrador' or
        (evento.get('estado_evento') != 'cerrado' and (
            current_user.rol == 'denadoi' or
            current_user.id == evento.get('autor') or
            es_organizador
        ))
    )
    
    return puede_registrar


def get_upcoming_events(collection_eventos, exclude_open_registration=True, limit=20):
    inicio_hoy = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    
    filtro = {'fecha_inicio': {'$gte': inicio_hoy}}
    if exclude_open_registration:
        filtro['registro_abierto'] = {'$ne': True}
    
    return list(collection_eventos.find(filtro).sort('fecha_inicio').limit(limit))


def get_past_events(collection_eventos, exclude_open_registration=True, limit=20):
    ahora = datetime.utcnow()
    
    filtro = {"fecha_inicio": {"$lt": ahora}}
    if exclude_open_registration:
        filtro['registro_abierto'] = {'$ne': True}
    
    return list(collection_eventos.find(filtro).sort("fecha_inicio", -1).limit(limit))


def get_user_events(collection_eventos, user_id, exclude_open_registration=True, event_type=None, limit=20):
    filtro = {"autor": user_id}
    if exclude_open_registration:
        filtro['registro_abierto'] = {'$ne': True}
    if event_type:
        filtro['tipo'] = event_type
    
    return list(collection_eventos.find(filtro).sort("fecha_inicio", -1).limit(limit))


def paginate_events(collection_eventos, filtro, page=1, per_page=20, sort_field="fecha_inicio", sort_order=-1):
    skip = (page - 1) * per_page
    
    total = collection_eventos.count_documents(filtro)
    total_pages = (total + per_page - 1) // per_page
    
    eventos = list(
        collection_eventos.find(filtro)
        .sort(sort_field, sort_order)
        .skip(skip)
        .limit(per_page)
    )
    
    return eventos, total, total_pages


def get_event_by_code(collection_eventos, codigo_evento):
    return collection_eventos.find_one({"codigo": codigo_evento})


def create_event(collection_eventos, event_data):
    return collection_eventos.insert_one(event_data)


def update_event(collection_eventos, codigo_evento, update_data):
    return collection_eventos.update_one({"codigo": codigo_evento}, {"$set": update_data})


def delete_event(collection_eventos, codigo_evento):
    return collection_eventos.delete_one({"codigo": codigo_evento})


def close_event(collection_eventos, codigo_evento):
    return collection_eventos.update_one(
        {"codigo": codigo_evento},
        {"$set": {"estado_evento": "cerrado"}}
    )