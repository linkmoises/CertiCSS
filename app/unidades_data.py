###
###
###  Este módulo centraliza las constantes y helpers para derivar la región
###  de las unidades ejecutoras, sin estado y sin circularidades de import.
###
###
from datetime import datetime, timedelta
import re
import unicodedata

PROVINCIA_A_REGION = {
    "Bocas Del Toro": "bocasdeltoro",
    "Coclé": "cocle",
    "Colón": "colon",
    "Chiriquí": "chiriqui",
    "Herrera": "herrera",
    "Los Santos": "lossantos",
    "Veraguas": "veraguas",
    "Panamá Oeste": "panamaoeste",
    "Panamá Este": "panamaeste",
    "Panamá": "panama",
}

REGION_A_CSS = {
    "panama": "css081",
    "sanmiguelito": "css088",
    "panamaoeste": "css13",
    "panamaeste": "css082",
    "bocasdeltoro": "css01",
    "cocle": "css02",
    "colon": "css03",
    "chiriqui": "css04",
    "herrera": "css06",
    "lossantos": "css07",
    "veraguas": "css09",
    "administrativas": "css00",
}

CSS_A_REGION = {value: key for key, value in REGION_A_CSS.items()}

REGION_LABEL = {
    "panama": "Panamá Metro",
    "sanmiguelito": "San Miguelito",
    "panamaoeste": "Panamá Oeste",
    "panamaeste": "Panamá Este",
    "bocasdeltoro": "Bocas del Toro",
    "cocle": "Coclé",
    "colon": "Colón",
    "chiriqui": "Chiriquí",
    "herrera": "Herrera",
    "lossantos": "Los Santos",
    "veraguas": "Veraguas",
    "administrativas": "Administrativas",
}

# Unidades conocidas de San Miguelito (compatibilidad: hoy tienen provincia "Panamá")
SAN_MIGUELITO_UNITS = {
    "Hospital Dra. Susana Jones Cano",
    "Policlínica Lic. Manuel María Valdés",
    "Policlínica Don Generoso Guardia",
    "Policlínica Dr. Edilberto Culiolis",
    "Policlínica Dra. Cecilia Guerra",
    "CAPPS Torrijos Carter",
}

_CACHE = {"timestamp": None, "por_region": None, "por_region_usuario": None}
CACHE_TTL = 60


def region_de_unidad(doc):
    if doc.get('region'):
        return doc['region']
    if doc.get('nombre') in SAN_MIGUELITO_UNITS:
        return 'sanmiguelito'
    return PROVINCIA_A_REGION.get(doc.get('provincia'), 'panama')


def region_usuario_de_unidad(doc):
    return REGION_A_CSS.get(region_de_unidad(doc), 'css00')


def categoria_de_unidad(doc):
    if doc.get('categoria'):
        return doc['categoria']
    if doc.get('tipo') == 'Coordinación Regional':
        return 'regional'
    return 'asistencial'


def invalidar_cache_unidades():
    _CACHE['timestamp'] = None
    _CACHE['por_region'] = None
    _CACHE['por_region_usuario'] = None


def _cache_vigente():
    if not _CACHE['timestamp']:
        return False
    return datetime.now() - _CACHE['timestamp'] < timedelta(seconds=CACHE_TTL)


def unidades_por_region():
    return _construir_por_region('por_region', REGION_A_CSS.keys())


def unidades_por_region_usuario():
    return _construir_por_region('por_region_usuario', REGION_A_CSS.values(), por_usuario=True)


def _construir_por_region(clave_cache, claves, por_usuario=False):
    if _cache_vigente() and _CACHE[clave_cache] is not None:
        return _CACHE[clave_cache]

    from app import collection_unidades

    unidades = list(collection_unidades.find(
        {"activo": True},
        {"nombre": 1, "provincia": 1, "tipo": 1, "categoria": 1, "region": 1}
    ))

    resultado = {}
    for unidad in unidades:
        nombre = unidad.get('nombre')
        if not nombre:
            continue
        region = region_usuario_de_unidad(unidad) if por_usuario else region_de_unidad(unidad)
        resultado.setdefault(region, []).append(nombre)

    orden = [clave for clave in claves if clave in resultado]
    extra = sorted(set(resultado) - set(claves))
    resultado_ordenado = {clave: sorted(resultado[clave]) for clave in orden}
    for clave in extra:
        resultado_ordenado[clave] = sorted(resultado[clave])

    _CACHE['timestamp'] = datetime.now()
    _CACHE[clave_cache] = resultado_ordenado
    return resultado_ordenado


def slugify(nombre):
    """Convierte un nombre en slug URL (sin acentos, minúsculas, guiones)."""
    texto = unicodedata.normalize('NFKD', nombre or '')
    texto = ''.join(c for c in texto if not unicodedata.combining(c))
    texto = re.sub(r'[^a-zA-Z0-9]+', '-', texto.lower()).strip('-')
    return texto or 'unidad'


def normalizar_texto(texto):
    """Minúsculas y sin acentos/espacios/puntuación, para comparar nombres."""
    texto = unicodedata.normalize('NFKD', texto or '')
    texto = ''.join(c for c in texto if not unicodedata.combining(c))
    return re.sub(r'[^a-z0-9]', '', texto.lower())


def nombres_equivalentes(doc):
    """[nombre] + (nombres_anteriores o []), con trim y dedup. Para lookups $in."""
    nombres = [str(doc.get('nombre') or '').strip()]
    nombres += [str(n).strip() for n in (doc.get('nombres_anteriores') or [])]
    vistos = set()
    resultado = []
    for n in nombres:
        if n and n not in vistos:
            vistos.add(n)
            resultado.append(n)
    return resultado


def resolver_unidad(nombre, region_hint=None):
    """Resuelve un nombre de unidad contra la colección `unidades`.

    - Busca por `nombre` exacto y por `nombres_anteriores`.
    - 1 doc  -> lo devuelve.
    - >1 con `region_hint` -> el doc cuya región coincide.
    - >1 sin hint (o ninguno) -> None (ambigüo/desconocido; el llamador decide).
    """
    from app import collection_unidades

    nombre = (nombre or '').strip()
    if not nombre:
        return None
    docs = list(collection_unidades.find({
        '$or': [
            {'nombre': nombre},
            {'nombres_anteriores': nombre},
        ]
    }))
    if len(docs) == 1:
        return docs[0]
    if len(docs) > 1 and region_hint:
        for doc in docs:
            if region_de_unidad(doc) == region_hint:
                return doc
    return None


def arbol_administrativas():
    """Árbol jerárquico de unidades administrativas (nodos {unidad, nivel, hijos})."""
    from app import collection_unidades

    docs = list(collection_unidades.find(
        {"categoria": "administrativa"},
        {"nombre": 1, "unidad_padre": 1, "activo": 1, "tipo": 1, "foto": 1, "slug": 1}
    ))
    if not docs:
        return []

    por_id = {str(d['_id']): d for d in docs}
    raices = []
    hijos_por_padre = {}
    for d in docs:
        padre = d.get('unidad_padre')
        clave = str(padre) if padre is not None else None
        if clave and clave in por_id:
            hijos_por_padre.setdefault(clave, []).append(d)
        else:
            raices.append(d)

    def ordenar(docs):
        docs.sort(key=lambda d: (not d.get('activo', True), (d.get('nombre') or '').lower()))

    ordenar(raices)
    for k in hijos_por_padre:
        ordenar(hijos_por_padre[k])

    visitados = set()

    def construir(d, nivel):
        visitados.add(str(d['_id']))
        nodo = {'unidad': d, 'nivel': nivel, 'hijos': []}
        for hijo in hijos_por_padre.get(str(d['_id']), []):
            if str(hijo['_id']) in visitados:
                continue
            nodo['hijos'].append(construir(hijo, nivel + 1))
        return nodo

    return [construir(r, 0) for r in raices]


def aplanar_arbol(nodos, nivel=0):
    """Convierte el árbol en lista plana [(doc, nivel)] en orden estructural."""
    resultado = []
    for nodo in nodos:
        resultado.append((nodo['unidad'], nivel))
        resultado.extend(aplanar_arbol(nodo['hijos'], nivel + 1))
    return resultado


def descendientes_administrativas(unidad_id):
    """Lista de _ids (str) de todas las descendientes de una administrativa (sin ella)."""
    from app import collection_unidades

    docs = list(collection_unidades.find(
        {"categoria": "administrativa"},
        {"_id": 1, "unidad_padre": 1}
    ))
    hijos_por_id = {}
    for d in docs:
        padre = d.get('unidad_padre')
        if padre is not None:
            hijos_por_id.setdefault(str(padre), []).append(str(d['_id']))
    resultado = []

    def recorrer(pid):
        for hid in hijos_por_id.get(pid, []):
            if hid in resultado:
                continue
            resultado.append(hid)
            recorrer(hid)

    recorrer(str(unidad_id))
    return resultado


def unidad_puede_ser_padre(unidad_id, candidato_padre_id):
    """Anti-ciclos: False si el candidato es la unidad o un descendiente de ella."""
    if not candidato_padre_id:
        return True
    if str(candidato_padre_id) == str(unidad_id):
        return False
    if str(candidato_padre_id) in descendientes_administrativas(unidad_id):
        return False
    return True


def opciones_jerarquizadas_por_region():
    """Dict región -> [(nombre, nivel)] para selects anidados (valor = nombre plano)."""
    arbol = arbol_administrativas()
    admin = aplanar_arbol(arbol)
    resultado = {'administrativas': [(u['nombre'], nivel) for u, nivel in admin]}
    return resultado
