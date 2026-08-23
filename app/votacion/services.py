import string
import random
from datetime import datetime
from pymongo import ASCENDING, DESCENDING, MongoClient


_collection_votaciones = None
_collection_votaciones_respuestas = None


def init_votacion_services(db):
    global _collection_votaciones, _collection_votaciones_respuestas
    _collection_votaciones = db['votaciones']
    _collection_votaciones_respuestas = db['votaciones_respuestas']

    _collection_votaciones.create_index([('codigo', ASCENDING)], unique=True)
    _collection_votaciones.create_index([('creador', ASCENDING)])
    _collection_votaciones.create_index([('fecha_creacion', DESCENDING)])
    _collection_votaciones_respuestas.create_index(
        [('votacion_id', ASCENDING), ('cedula', ASCENDING)], unique=True
    )
    _collection_votaciones_respuestas.create_index([('votacion_id', ASCENDING)])


def get_collection_votaciones():
    return _collection_votaciones


def get_collection_respuestas():
    return _collection_votaciones_respuestas


def generar_codigo_votacion(longitud=8):
    caracteres = string.ascii_uppercase + string.digits
    while True:
        codigo = ''.join(random.choice(caracteres) for _ in range(longitud))
        if _collection_votaciones.find_one({"codigo": codigo}) is None:
            return codigo


def crear_votacion(titulo, descripcion, tipo_pregunta, opciones, creador):
    codigo = generar_codigo_votacion()
    doc = {
        'codigo': codigo,
        'titulo': titulo.strip(),
        'descripcion': descripcion.strip() if descripcion else '',
        'tipo_pregunta': tipo_pregunta,
        'opciones': opciones,
        'creador': str(creador),
        'fecha_creacion': datetime.utcnow(),
        'estado': 'abierta',
    }
    result = _collection_votaciones.insert_one(doc)
    doc['_id'] = result.inserted_id
    return doc


def obtener_votacion_por_codigo(codigo):
    return _collection_votaciones.find_one({"codigo": codigo})


def obtener_votaciones_por_creador(creador):
    return list(
        _collection_votaciones.find({"creador": str(creador)}).sort("fecha_creacion", DESCENDING)
    )


def obtener_todas_votaciones(estado=None):
    filtro = {"estado": estado} if estado in ('abierta', 'cerrada') else {}
    return list(
        _collection_votaciones.find(filtro).sort("fecha_creacion", DESCENDING)
    )


def actualizar_votacion(codigo, datos):
    _collection_votaciones.update_one({"codigo": codigo}, {"$set": datos})


def cerrar_votacion(codigo):
    _collection_votaciones.update_one(
        {"codigo": codigo}, {"$set": {"estado": "cerrada", "fecha_cierre": datetime.utcnow()}}
    )


def eliminar_votacion(codigo):
    _collection_votaciones.delete_one({"codigo": codigo})
    _collection_votaciones_respuestas.delete_many({"votacion_id": codigo})


def registrar_voto(codigo_votacion, cedula, nombre, opcion_elegida):
    from bson import ObjectId
    votacion = _collection_votaciones.find_one({"codigo": codigo_votacion})
    if not votacion:
        return False, "Votacion no encontrada"
    if votacion.get('estado') != 'abierta':
        return False, "Esta votacion ya esta cerrada"

    existente = _collection_votaciones_respuestas.find_one({
        "votacion_id": codigo_votacion,
        "cedula": cedula.strip()
    })
    if existente:
        return False, "Ya has participado en esta votacion"

    doc = {
        'votacion_id': codigo_votacion,
        'cedula': cedula.strip(),
        'nombre': nombre.strip(),
        'opcion_elegida': opcion_elegida.strip(),
        'fecha': datetime.utcnow(),
    }
    _collection_votaciones_respuestas.insert_one(doc)
    return True, "Voto registrado exitosamente"


def contar_votos_por_opcion(codigo_votacion):
    pipeline = [
        {"$match": {"votacion_id": codigo_votacion}},
        {"$group": {"_id": "$opcion_elegida", "total": {"$sum": 1}}},
        {"$sort": {"total": -1}},
    ]
    resultados = list(_collection_votaciones_respuestas.aggregate(pipeline))
    votacion = _collection_votaciones.find_one({"codigo": codigo_votacion})
    total = sum(r['total'] for r in resultados)

    opciones_conteo = {}
    if votacion:
        for op in votacion.get('opciones', []):
            texto = op.get('texto', '') if isinstance(op, dict) else str(op)
            opciones_conteo[texto] = 0

    for r in resultados:
        opciones_conteo[r['_id']] = r['total']

    return opciones_conteo, total


def obtener_respuestas(codigo_votacion):
    return list(
        _collection_votaciones_respuestas.find({"votacion_id": codigo_votacion}).sort("fecha", ASCENDING)
    )


def ya_voto(codigo_votacion, cedula):
    return _collection_votaciones_respuestas.find_one({
        "votacion_id": codigo_votacion,
        "cedula": cedula.strip()
    }) is not None
