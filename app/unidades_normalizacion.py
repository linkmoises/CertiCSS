###
###
###  Lógica pura de normalización de renombramientos históricos de unidades.
###  No importa Flask: recibe las colecciones de Mongo por parámetro para ser
###  testeable con colecciones mockeadas y reutilizable desde las rutas.
###
###
import re
import unicodedata
from datetime import datetime

from app.unidades_data import (
    REGION_A_CSS,
    CSS_A_REGION,
    normalizar_texto,
    region_de_unidad,
)


def _parse_fecha(valor):
    if valor is None:
        return None
    if isinstance(valor, datetime):
        return valor
    if isinstance(valor, str):
        texto = valor.strip()
        try:
            return datetime.fromisoformat(texto.replace('Z', '+00:00'))
        except ValueError:
            pass
        try:
            return datetime.strptime(texto, '%Y-%m-%d')
        except ValueError:
            pass
    return None


def _tokens(texto):
    texto = unicodedata.normalize('NFKD', texto or '').lower()
    texto = ''.join(c for c in texto if not unicodedata.combining(c))
    return set(re.findall(r'[a-z0-9]+', texto))


def _serializar_doc(doc):
    from bson.objectid import ObjectId

    out = {}
    for k, v in doc.items():
        if isinstance(v, ObjectId):
            out[k] = str(v)
        elif isinstance(v, datetime):
            out[k] = v.isoformat()
        elif isinstance(v, dict):
            out[k] = _serializar_doc(v)
        elif isinstance(v, list):
            out[k] = [_serializar_doc(i) if isinstance(i, dict) else (str(i) if isinstance(i, (ObjectId, datetime)) else i) for i in v]
        else:
            out[k] = v
    return out


def _resumen(clasificacion):
    return {k: len(v) for k, v in clasificacion.items()}


def _clasificar_por_fecha(registros, fecha_corte, campo_fecha, region_objetivo):
    """Clasifica registros en post_fecha / pre_fecha / sin_clasificar / otra_region."""
    clasif = {'post_fecha': [], 'pre_fecha': [], 'sin_clasificar': [], 'otra_region': []}
    for reg in registros:
        region_reg = reg.get('region')
        if region_objetivo:
            if not region_reg:
                clasif['sin_clasificar'].append(reg)
                continue
            if region_reg != region_objetivo:
                clasif['otra_region'].append(reg)
                continue
        fecha = _parse_fecha(reg.get(campo_fecha))
        if not fecha:
            clasif['sin_clasificar'].append(reg)
        elif fecha_corte is None or fecha >= fecha_corte:
            clasif['post_fecha'].append(reg)
        else:
            clasif['pre_fecha'].append(reg)
    return clasif


def _es_post(reg, fecha_corte, campo_fecha, region_objetivo):
    region_reg = reg.get('region')
    if region_objetivo:
        if not region_reg or region_reg != region_objetivo:
            return False
    fecha = _parse_fecha(reg.get(campo_fecha))
    if not fecha:
        return False
    if fecha_corte is None or fecha >= fecha_corte:
        return True
    return False


def _join_fecha_participantes(col_eventos, participantes):
    codigos = {p.get('codigo_evento') for p in participantes if p.get('codigo_evento')}
    eventos = {}
    if codigos:
        for ev in col_eventos.find(
            {'codigo': {'$in': list(codigos)}},
            {'codigo': 1, 'fecha_inicio': 1, 'region': 1}
        ):
            eventos[ev.get('codigo')] = ev
    return eventos


def validar_colisiones(doc, col_unidades):
    """Valida un renombramiento y devuelve la lista de problemas (vacía si OK)."""
    nombre_viejo = (doc.get('nombre_anterior') or '').strip()
    canonico = (doc.get('canonico') or '').strip()
    region = doc.get('region')

    problemas = []
    if not nombre_viejo:
        problemas.append('Falta el nombre anterior.')
    if not canonico:
        problemas.append('Falta el nombre canónico.')

    unidad_canonica = None
    if canonico:
        if region:
            unidad_canonica = col_unidades.find_one({'nombre': canonico, 'region': region})
            if not unidad_canonica:
                unidad_canonica = col_unidades.find_one({'nombre': canonico})
        else:
            unidad_canonica = col_unidades.find_one({'nombre': canonico})
        if not unidad_canonica:
            problemas.append(f'No existe una unidad canónica "{canonico}".')
        else:
            canonicos = list(col_unidades.find({'nombre': canonico}))
            if len(canonicos) > 1 and not region:
                problemas.append(f'"{canonico}" existe en varias regiones; se requiere la región.')

    if nombre_viejo and region and unidad_canonica:
        colision = col_unidades.find_one({
            'region': region,
            '_id': {'$ne': unidad_canonica['_id']},
            '$or': [
                {'nombre': nombre_viejo},
                {'nombres_anteriores': nombre_viejo},
            ],
        })
        if colision:
            problemas.append(f'"{nombre_viejo}" ya es usado por la unidad "{colision.get("nombre")}" de la región "{region}".')

    return problemas


def revisar_renombramiento(doc, col_unidades, col_eventos, col_participantes, col_usuarios):
    """Clasifica registros (unidad, región) según fecha de referencia.

    Devuelve pre-fecha (conserva, lo cubre el alias), post-fecha (se normalizará),
    sin-clasificar (sin fecha/evento/región -> solo listado), otra-región (homónimos),
    y las colisiones validadas.
    """
    nombre_viejo = (doc.get('nombre_anterior') or '').strip()
    region = doc.get('region')
    fecha_corte = _parse_fecha(doc.get('fecha_renombre'))
    region_usuario = REGION_A_CSS.get(region) if region else None

    colisiones = validar_colisiones(doc, col_unidades)

    eventos = list(col_eventos.find({'unidad_ejecutora': nombre_viejo})) if nombre_viejo else []
    resultado_eventos = _clasificar_por_fecha(eventos, fecha_corte, 'fecha_inicio', region)

    usuarios = list(col_usuarios.find({'unidad_ejecutora': nombre_viejo})) if nombre_viejo else []
    resultado_usuarios = _clasificar_por_fecha(usuarios, fecha_corte, 'timestamp', region_usuario)

    participantes = list(col_participantes.find({'unidad': nombre_viejo})) if nombre_viejo else []
    eventos_join = _join_fecha_participantes(col_eventos, participantes)
    resultado_participantes = {'post_fecha': [], 'pre_fecha': [], 'sin_clasificar': [], 'otra_region': []}
    for p in participantes:
        region_reg = p.get('region')
        if region:
            if not region_reg:
                resultado_participantes['sin_clasificar'].append(p)
                continue
            if region_reg != region:
                resultado_participantes['otra_region'].append(p)
                continue
        ev = eventos_join.get(p.get('codigo_evento'))
        fecha = _parse_fecha(ev.get('fecha_inicio')) if ev else None
        if not fecha:
            resultado_participantes['sin_clasificar'].append(p)
        elif fecha_corte is None or fecha >= fecha_corte:
            resultado_participantes['post_fecha'].append(p)
        else:
            resultado_participantes['pre_fecha'].append(p)

    return {
        'eventos': resultado_eventos,
        'participantes': resultado_participantes,
        'usuarios': resultado_usuarios,
        'colisiones': colisiones,
        'totales': {
            'eventos': _resumen(resultado_eventos),
            'participantes': _resumen(resultado_participantes),
            'usuarios': _resumen(resultado_usuarios),
        },
    }


def aplicar_renombramiento(doc, col_unidades, col_eventos, col_participantes, col_usuarios,
                           col_renombramientos=None, usuario_email=None):
    """Aplica un mapeo de renombramiento confirmado.

    - Registra el nombre viejo en `nombres_anteriores` del canónico (solo `unidades`).
    - Normaliza nombre viejo -> canónico en registros post-fecha filtrados por (unidad, región).
    - Nunca toca pre-fecha, sin-clasificar ni homónimos de otra región.
    - Marca el renombramiento como `aplicado`.
    """
    if doc.get('estado') == 'aplicado':
        raise ValueError('Este renombramiento ya fue aplicado (estado=aplicado).')

    nombre_viejo = (doc.get('nombre_anterior') or '').strip()
    canonico = (doc.get('canonico') or '').strip()
    region = doc.get('region')
    fecha_corte = _parse_fecha(doc.get('fecha_renombre'))
    region_usuario = REGION_A_CSS.get(region) if region else None

    if not nombre_viejo or not canonico:
        raise ValueError('Faltan los nombres del renombramiento.')

    col_unidades.update_one(
        {'nombre': canonico, 'region': region} if region else {'nombre': canonico},
        {'$addToSet': {'nombres_anteriores': nombre_viejo}}
    )

    conteo = {'unidades': 1, 'eventos': 0, 'participantes': 0, 'usuarios': 0}

    eventos = list(col_eventos.find({'unidad_ejecutora': nombre_viejo}))
    ids_eventos = [e['_id'] for e in eventos if _es_post(e, fecha_corte, 'fecha_inicio', region)]
    if ids_eventos:
        col_eventos.update_many({'_id': {'$in': ids_eventos}}, {'$set': {'unidad_ejecutora': canonico}})
        conteo['eventos'] = len(ids_eventos)

    usuarios = list(col_usuarios.find({'unidad_ejecutora': nombre_viejo}))
    ids_usuarios = [u['_id'] for u in usuarios if _es_post(u, fecha_corte, 'timestamp', region_usuario)]
    if ids_usuarios:
        col_usuarios.update_many({'_id': {'$in': ids_usuarios}}, {'$set': {'unidad_ejecutora': canonico}})
        conteo['usuarios'] = len(ids_usuarios)

    participantes = list(col_participantes.find({'unidad': nombre_viejo}))
    eventos_join = _join_fecha_participantes(col_eventos, participantes)
    ids_participantes = []
    for p in participantes:
        region_reg = p.get('region')
        if region:
            if not region_reg or region_reg != region:
                continue
        ev = eventos_join.get(p.get('codigo_evento'))
        fecha = _parse_fecha(ev.get('fecha_inicio')) if ev else None
        if not fecha:
            continue
        if fecha_corte is None or fecha >= fecha_corte:
            ids_participantes.append(p['_id'])
    if ids_participantes:
        col_participantes.update_many({'_id': {'$in': ids_participantes}}, {'$set': {'unidad': canonico}})
        conteo['participantes'] = len(ids_participantes)

    if col_renombramientos is not None:
        update = {'estado': 'aplicado', 'aplicado_en': datetime.now()}
        if usuario_email:
            update['aplicado_por'] = usuario_email
        col_renombramientos.update_one({'_id': doc['_id']}, {'$set': update})

    return conteo


def _regiones_de_nombre(col_participantes, col_eventos, col_usuarios, nombre):
    conteo = {}
    for region in col_participantes.distinct('region', {'unidad': nombre}):
        if not region:
            continue
        n = col_participantes.count_documents({'unidad': nombre, 'region': region})
        conteo[region] = conteo.get(region, 0) + n
    for region in col_eventos.distinct('region', {'unidad_ejecutora': nombre}):
        if not region:
            continue
        n = col_eventos.count_documents({'unidad_ejecutora': nombre, 'region': region})
        conteo[region] = conteo.get(region, 0) + n
    for region in col_usuarios.distinct('region', {'unidad_ejecutora': nombre}):
        if not region:
            continue
        slug = CSS_A_REGION.get(region, region)
        n = col_usuarios.count_documents({'unidad_ejecutora': nombre, 'region': region})
        conteo[slug] = conteo.get(slug, 0) + n
    return conteo


def _candidatos_por_similitud(nombre, unidades, umbral=0.45):
    objetivo_tokens = _tokens(nombre)
    objetivo_norm = normalizar_texto(nombre)
    candidatos = []
    vistos = set()
    for u in unidades:
        nombres_u = [u.get('nombre')] + list(u.get('nombres_anteriores') or [])
        for n_u in nombres_u:
            if not n_u:
                continue
            clave = (u.get('nombre'), region_de_unidad(u))
            if clave in vistos:
                continue
            vistos.add(clave)
            if normalizar_texto(n_u) == objetivo_norm:
                score = 1.0
            else:
                tok = _tokens(n_u)
                inter = len(objetivo_tokens & tok)
                union = len(objetivo_tokens | tok) or 1
                score = inter / union
            if score >= umbral:
                candidatos.append({
                    'unidad': u.get('nombre'),
                    'region': region_de_unidad(u),
                    'id': str(u.get('_id')),
                    'score': round(score, 2),
                })
                break
    candidatos.sort(key=lambda c: -c['score'])
    return candidatos[:5]


def _homonimos_misma_region(unidades):
    agrupado = {}
    for u in unidades:
        nombre = u.get('nombre')
        if not nombre:
            continue
        agrupado.setdefault((nombre, region_de_unidad(u)), []).append(u)
    advertencias = []
    for (nombre, region), docs in agrupado.items():
        if len(docs) > 1:
            advertencias.append({'nombre': nombre, 'region': region, 'cantidad': len(docs)})
    return advertencias


def _upsert_propuesta(col_renombramientos, nombre, candidato, region):
    if not candidato:
        return None
    canonico = candidato['unidad']
    existente = col_renombramientos.find_one({'nombre_anterior': nombre, 'canonico': canonico})
    doc = {
        'nombre_anterior': nombre,
        'canonico': canonico,
        'region': region or candidato.get('region'),
        'estado': 'propuesto',
    }
    if existente:
        col_renombramientos.update_one({'_id': existente['_id']}, {'$set': doc})
        return existente['_id']
    return col_renombramientos.insert_one(doc).inserted_id


def detectar_renombramientos(col_unidades, col_eventos, col_participantes, col_usuarios, col_renombramientos):
    """Escanea nombres distintos y propone renombramientos para los huérfanos."""
    unidades = list(col_unidades.find({}))
    docs_por_nombre = {}
    for u in unidades:
        docs_por_nombre.setdefault(u.get('nombre'), []).append(u)
        for alias in (u.get('nombres_anteriores') or []):
            docs_por_nombre.setdefault(alias, []).append(u)

    nombres_registros = set()
    for nombre in col_participantes.distinct('unidad'):
        if nombre and str(nombre).strip():
            nombres_registros.add(str(nombre).strip())
    for nombre in col_eventos.distinct('unidad_ejecutora'):
        if nombre and str(nombre).strip():
            nombres_registros.add(str(nombre).strip())
    for nombre in col_usuarios.distinct('unidad_ejecutora'):
        if nombre and str(nombre).strip():
            nombres_registros.add(str(nombre).strip())

    huerfanos = []
    propuestas = []
    for nombre in sorted(nombres_registros):
        if docs_por_nombre.get(nombre):
            continue
        regiones = _regiones_de_nombre(col_participantes, col_eventos, col_usuarios, nombre)
        region_objetivo = max(regiones, key=regiones.get) if regiones else None
        candidatos = _candidatos_por_similitud(nombre, unidades)
        huerfanos.append({
            'nombre': nombre,
            'regiones': sorted(regiones),
            'region': region_objetivo,
            'candidatos': candidatos,
        })
        if candidatos:
            propuestas.append(_upsert_propuesta(col_renombramientos, nombre, candidatos[0], region_objetivo))

    return {
        'huerfanos': huerfanos,
        'propuestas': propuestas,
        'advertencias': _homonimos_misma_region(unidades),
        'total_nombres': len(nombres_registros),
        'total_huerfanos': len(huerfanos),
    }


def resumen_huerfanos(col_unidades, col_eventos, col_participantes, col_usuarios):
    """Cobertura del report: verifica que no quedan (nombre) huérfanos mapeados."""
    nombres_validos = set()
    for u in col_unidades.find({}):
        nombres_validos.add(u.get('nombre'))
        for alias in (u.get('nombres_anteriores') or []):
            if alias:
                nombres_validos.add(alias)

    nombres_registros = set()
    for nombre in col_participantes.distinct('unidad'):
        if nombre and str(nombre).strip():
            nombres_registros.add(str(nombre).strip())
    for nombre in col_eventos.distinct('unidad_ejecutora'):
        if nombre and str(nombre).strip():
            nombres_registros.add(str(nombre).strip())
    for nombre in col_usuarios.distinct('unidad_ejecutora'):
        if nombre and str(nombre).strip():
            nombres_registros.add(str(nombre).strip())

    huerfanos = sorted(n for n in nombres_registros if n not in nombres_validos)
    return {
        'huerfanos': huerfanos,
        'total_huerfanos': len(huerfanos),
        'resueltos': len(nombres_registros) - len(huerfanos),
        'total_nombres': len(nombres_registros),
    }


def generar_respaldo(doc, col_unidades, col_eventos, col_participantes, col_usuarios):
    """Snapshot de los documentos post-fecha que se modificarían al aplicar."""
    revision = revisar_renombramiento(doc, col_unidades, col_eventos, col_participantes, col_usuarios)
    return {
        'generado': datetime.now().isoformat(),
        'renombramiento': _serializar_doc(doc),
        'eventos': [_serializar_doc(e) for e in revision['eventos']['post_fecha']],
        'participantes': [_serializar_doc(p) for p in revision['participantes']['post_fecha']],
        'usuarios': [_serializar_doc(u) for u in revision['usuarios']['post_fecha']],
    }
