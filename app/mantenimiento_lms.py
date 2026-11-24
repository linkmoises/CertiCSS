"""Enlaces estables para resultados históricos del LMS.

Los intentos de examen y las entregas de tarea nuevos guardan el id del
contenido (`examen_id`/`tarea_id`). Los registros históricos solo guardan el
orden, que cambia al reordenar contenidos. Este módulo rellena el enlace
estable emparejando por título normalizado; solo asigna cuando la coincidencia
es única (o cuando el orden desempata entre títulos repetidos).
"""

from app import (
    collection_eva,
    collection_exam_results,
    collection_tarea_entregas,
)

# (grupo, colección, campo_fk, campo_titulo, campo_orden, tipo_contenido)
CAMPOS = (
    (
        "examenes",
        collection_exam_results,
        "examen_id",
        "titulo_examen",
        "orden_examen",
        "examen",
    ),
    (
        "tareas",
        collection_tarea_entregas,
        "tarea_id",
        "titulo_tarea",
        "orden_tarea",
        "tarea",
    ),
)


def normalizar_titulo(texto):
    """Normaliza un título para comparar sin espacios ni mayúsculas de más."""
    return " ".join(str(texto or "").split()).strip().casefold()


def _consulta_sin_enlace(campo_fk, codigo_evento=None):
    consulta = {"$or": [{campo_fk: None}, {campo_fk: {"$exists": False}}]}
    if codigo_evento:
        consulta["codigo_evento"] = codigo_evento
    return consulta


def contar_sin_enlace(codigo_evento):
    """Cantidad de intentos/entregas que aún dependen del orden."""
    examenes = collection_exam_results.count_documents(
        _consulta_sin_enlace("examen_id", codigo_evento)
    )
    tareas = collection_tarea_entregas.count_documents(
        _consulta_sin_enlace("tarea_id", codigo_evento)
    )
    return examenes, tareas


def _resumen(doc, codigo_evento, campo_titulo, campo_orden):
    return {
        "id": str(doc.get("_id")),
        "evento": codigo_evento,
        "cedula": doc.get("cedula_participante"),
        "titulo": doc.get(campo_titulo),
        "orden": doc.get(campo_orden),
    }


def _elegir_contenido(doc, candidatos, campo_titulo, campo_orden):
    """Devuelve (contenido|None, motivo). Solo asigna con evidencia única."""
    titulo = normalizar_titulo(doc.get(campo_titulo))
    if not titulo:
        return None, "sin_titulo"

    coincidencias = [
        c
        for c in candidatos
        if normalizar_titulo(c.get("titulo")) == titulo
    ]
    if len(coincidencias) == 1:
        return coincidencias[0], None
    if not coincidencias:
        # Evento con un solo examen/tarea: aunque el título se haya cambiado,
        # el registro solo puede pertenecer a ese contenido.
        if len(candidatos) == 1:
            return candidatos[0], None
        return None, "sin_coincidencia"

    # Títulos repetidos: el orden original desempata si apunta a uno solo.
    por_orden = [
        c for c in coincidencias if c.get("orden") == doc.get(campo_orden)
    ]
    if len(por_orden) == 1:
        return por_orden[0], None
    return None, "ambiguo"


def backfill_enlaces_lms(codigo_evento=None, aplicar=False):
    """Rellena examen_id/tarea_id en los registros históricos.

    `aplicar=False` es un ensayo: informa qué haría sin escribir. Solo
    actualiza el enlace (y el orden de respaldo si estaba desalineado), nunca
    calificaciones ni respuestas.
    """
    eventos = (
        [codigo_evento]
        if codigo_evento
        else sorted(collection_eva.distinct("codigo_evento"))
    )
    reporte = {}

    for grupo, coleccion, campo_fk, campo_titulo, campo_orden, tipo in CAMPOS:
        detalle = {
            "revisados": 0,
            "actualizables": 0,
            "actualizados": 0,
            "ambiguos": [],
            "sin_coincidencia": [],
            "sin_titulo": [],
        }
        for evento in eventos:
            contenidos = list(
                collection_eva.find(
                    {"codigo_evento": evento, "tipo": tipo},
                    {"orden": 1, "titulo": 1},
                )
            )
            pendientes = coleccion.find(
                _consulta_sin_enlace(campo_fk, evento)
            )
            for doc in pendientes:
                detalle["revisados"] += 1
                elegido, motivo = _elegir_contenido(
                    doc, contenidos, campo_titulo, campo_orden
                )
                if elegido is None:
                    clave = {
                        "ambiguo": "ambiguos",
                        "sin_coincidencia": "sin_coincidencia",
                        "sin_titulo": "sin_titulo",
                    }[motivo]
                    detalle[clave].append(
                        _resumen(doc, evento, campo_titulo, campo_orden)
                    )
                    continue

                detalle["actualizables"] += 1
                if not aplicar:
                    continue

                cambios = {campo_fk: str(elegido["_id"])}
                if doc.get(campo_orden) != elegido.get("orden"):
                    cambios[campo_orden] = elegido.get("orden")
                    cambios["_remap_orden_previo"] = doc.get(campo_orden)
                coleccion.update_one({"_id": doc["_id"]}, {"$set": cambios})
                detalle["actualizados"] += 1

        reporte[grupo] = detalle

    return reporte
