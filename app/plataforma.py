import os
import re
import uuid
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
    collection_progreso,
    collection_qbanks,
    collection_qbanks_data,
    collection_tarea_entregas,
    db,
)
from app.auth import token_required, lms_required, lms_edit_required
from app.mantenimiento_lms import contar_sin_enlace

plataforma_bp = Blueprint("plataforma", __name__)


###
### LMS jerárquico: Módulo -> Submódulo -> Contenido (+ huérfanos)
### Backward-compatible: cursos planos existentes (sin modulo_id/
### submodulo_id) se tratan como huérfanos y se renderizan igual que antes.
###
TIPOS_NO_NAVEGABLES = {"modulo", "submodulo"}
TIPOS_NAVEGABLES_EXAMEN = {"video", "texto", "documento", "caso_chatgpt", "examen", "tarea"}

# Umbral de aprobación para evaluaciones sumativas y tareas manuales.
UMBRAL_APROBACION = 80


def es_navegable(contenido):
    """Un contenido es navegable si su tipo no es módulo/submódulo."""
    return contenido.get("tipo") not in TIPOS_NO_NAVEGABLES


def _id_str(doc):
    try:
        return str(doc.get("_id")) if doc.get("_id") is not None else None
    except Exception:
        return None


def build_arbol_lms(contenidos):
    """Construye árbol {huerfanos, modulos:[{doc, contenidos_directos, submodulos:[{doc, contenidos}]}]}.

    Acepta docs legacy sin modulo_id/submodulo_id (los trata como huérfanos).
    """
    modulos_by_id = {}
    submodulos_by_id = {}
    for c in contenidos:
        if c.get("tipo") == "modulo":
            modulos_by_id[_id_str(c)] = {
                "doc": c, "contenidos_directos": [], "submodulos": [],
            }
        elif c.get("tipo") == "submodulo":
            submodulos_by_id[_id_str(c)] = {"doc": c, "contenidos": []}

    # Vincular submódulos a su módulo padre (huérfano si el padre no existe)
    submodulos_huerfanos = []
    for sid, nodo in submodulos_by_id.items():
        mid = nodo["doc"].get("modulo_id")
        if mid and str(mid) in modulos_by_id:
            modulos_by_id[str(mid)]["submodulos"].append(nodo)
        else:
            submodulos_huerfanos.append(nodo)

    huerfanos = list(submodulos_huerfanos)
    modulos = []
    for mid, nodo in modulos_by_id.items():
        modulos.append(nodo)
    # Ordenar módulos/submódulos por `orden` para display estable
    modulos.sort(key=lambda n: n["doc"].get("orden", 0))
    for nodo in modulos:
        nodo["submodulos"].sort(key=lambda s: s["doc"].get("orden", 0))

    sub_por_id = {k: v for k, v in submodulos_by_id.items()}
    for c in contenidos:
        if c.get("tipo") in TIPOS_NO_NAVEGABLES:
            continue
        mid = c.get("modulo_id")
        sid = c.get("submodulo_id")
        mid = str(mid) if mid else None
        sid = str(sid) if sid else None
        if sid and sid in sub_por_id:
            # Validar coherencia: el submódulo debe colgar del mismo módulo
            sub_mid = sub_por_id[sid]["doc"].get("modulo_id")
            sub_mid = str(sub_mid) if sub_mid else None
            if mid and sub_mid and mid != sub_mid:
                huerfanos.append(c)
                continue
            sub_por_id[sid]["contenidos"].append(c)
        elif mid and mid in modulos_by_id:
            modulos_by_id[mid]["contenidos_directos"].append(c)
        else:
            huerfanos.append(c)

    # Ordenar contenidos por `orden` dentro de cada grupo
    huerfanos.sort(key=lambda c: c.get("orden", 0) if isinstance(c, dict) else 0)
    for nodo in modulos:
        nodo["contenidos_directos"].sort(key=lambda c: c.get("orden", 0))
        for sub in nodo["submodulos"]:
            sub["contenidos"].sort(key=lambda c: c.get("orden", 0))
    # huerfanos puede mezclar dicts de submódulo-nodo y contenidos; normalizar
    huerfanos_docs = []
    for h in huerfanos:
        if isinstance(h, dict) and "doc" in h and "contenidos" in h:
            huerfanos_docs.append(h)  # nodo submódulo huérfano
        else:
            huerfanos_docs.append(h)
    return {"huerfanos": huerfanos_docs, "modulos": modulos}


def breadcrumb_lms(contenidos_by_id, contenido):
    """Retorna (modulo_doc|None, submodulo_doc|None) para un contenido."""
    mid = contenido.get("modulo_id")
    sid = contenido.get("submodulo_id")
    mid = str(mid) if mid else None
    sid = str(sid) if sid else None
    modulo = contenidos_by_id.get(mid) if mid else None
    submodulo = contenidos_by_id.get(sid) if sid else None
    if modulo is not None and modulo.get("tipo") != "modulo":
        modulo = None
    if submodulo is not None and submodulo.get("tipo") != "submodulo":
        submodulo = None
    return modulo, submodulo


def puede_calificar_evento(evento):
    """¿Puede el usuario actual calificar tareas manuales de este evento?

    Pueden: administradores, rol denadoi, autor del evento y
    coorganizadores registrados en participantes con cuenta (match por
    cédula, igual que el resto del sistema).
    """
    if not current_user.is_authenticated:
        return False
    if getattr(current_user, "rol", None) in ("administrador", "denadoi"):
        return True
    try:
        if str(current_user.id) == str(evento.get("autor")):
            return True
    except Exception:
        pass
    cedula = getattr(current_user, "cedula", None)
    if not cedula:
        return False
    return collection_participantes.find_one(
        {
            "codigo_evento": evento.get("codigo"),
            "cedula": str(cedula),
            "rol": "coorganizador",
        }
    ) is not None


###
### LMS secuencial: progreso por contenido y desbloqueo en orden
###
UMBRAL_VIDEO_PORCENTAJE = 50
# Ventana máxima de reproducción aceptada en un solo reporte del reproductor.
MAX_DELTA_SEGUNDOS = 30.0


def secuencial_activo(evento):
    """¿El evento exige completar cada contenido antes de avanzar?"""
    return bool(evento.get("lms_secuencial"))


def clave_contenido(contenido):
    """Identificador estable de un contenido para el registro de progreso."""
    return _id_str(contenido) or f"orden:{contenido.get('orden')}"


def youtube_video_id(url):
    """Extrae el ID de un video de YouTube desde cualquier forma de URL."""
    if not url:
        return None
    texto = str(url).strip()
    for patron in (
        r"youtu\.be/([A-Za-z0-9_-]{11})",
        r"youtube(?:-nocookie)?\.com/embed/([A-Za-z0-9_-]{11})",
        r"youtube(?:-nocookie)?\.com/shorts/([A-Za-z0-9_-]{11})",
        r"youtube(?:-nocookie)?\.com/live/([A-Za-z0-9_-]{11})",
        r"youtube(?:-nocookie)?\.com/v/([A-Za-z0-9_-]{11})",
        r"[?&]v=([A-Za-z0-9_-]{11})",
    ):
        coincidencia = re.search(patron, texto)
        if coincidencia:
            return coincidencia.group(1)
    return None


def url_video_embed(url):
    """URL de embed con la IFrame API habilitada, o None si no es YouTube."""
    video_id = youtube_video_id(url)
    if not video_id:
        return None
    return f"https://www.youtube.com/embed/{video_id}?enablejsapi=1&rel=0"


def guardar_material_pdf(archivo, codigo_evento):
    """Guarda la presentación PDF opcional de un video.

    Devuelve (ruta_relativa, nombre_original) o (None, None) si no se subió
    archivo. Lanza ValueError si el archivo no es PDF.
    """
    if not archivo or not archivo.filename:
        return None, None
    if not archivo.filename.lower().endswith(".pdf"):
        raise ValueError("La presentación debe ser un archivo PDF.")
    evento_folder = os.path.join(current_app.config["UPLOAD_FOLDER"], codigo_evento)
    os.makedirs(evento_folder, exist_ok=True)
    nombre_archivo = f"presentacion-{codigo_evento}-{uuid.uuid4().hex[:8]}.pdf"
    archivo.save(os.path.join(evento_folder, nombre_archivo))
    nombre_original = os.path.basename(archivo.filename)[:120]
    return f"{codigo_evento}/{nombre_archivo}", nombre_original


def _progreso_del_participante(codigo_evento, cedula):
    if not cedula:
        return {}
    return {
        doc.get("contenido_id"): doc
        for doc in collection_progreso.find(
            {"codigo_evento": codigo_evento, "cedula_participante": str(cedula)}
        )
    }


def _examen_enviado(codigo_evento, cedula, contenido):
    return collection_exam_results.find_one(
        {
            "codigo_evento": codigo_evento,
            "cedula_participante": str(cedula),
            "$or": [
                {"examen_id": clave_contenido(contenido)},
                {"examen_id": None, "orden_examen": contenido.get("orden")},
                {
                    "examen_id": {"$exists": False},
                    "orden_examen": contenido.get("orden"),
                },
            ],
        }
    ) is not None


def _tarea_enviada(codigo_evento, cedula, contenido):
    return collection_tarea_entregas.find_one(
        {
            "codigo_evento": codigo_evento,
            "cedula_participante": str(cedula),
            "$or": [
                {"tarea_id": clave_contenido(contenido)},
                {"tarea_id": None, "orden_tarea": contenido.get("orden")},
                {
                    "tarea_id": {"$exists": False},
                    "orden_tarea": contenido.get("orden"),
                },
            ],
        }
    ) is not None


def contenido_se_completa_al_abrir(contenido):
    """¿Basta abrir el contenido para darlo por completado?"""
    tipo = contenido.get("tipo")
    if tipo == "video":
        # Sin ID de YouTube no se puede medir reproducción: se completa al abrir.
        return youtube_video_id(contenido.get("url_video")) is None
    if tipo == "examen":
        return not contenido.get("qbank_config")
    if tipo == "tarea":
        return not contenido.get("requiere_entrega")
    return es_navegable(contenido)


def contenido_completado(codigo_evento, cedula, contenido, progreso=None):
    """Estado de completitud de un contenido según su tipo y el progreso."""
    tipo = contenido.get("tipo")
    if tipo == "examen" and contenido.get("qbank_config"):
        return _examen_enviado(codigo_evento, cedula, contenido)
    if tipo == "tarea" and contenido.get("requiere_entrega"):
        return _tarea_enviada(codigo_evento, cedula, contenido)
    if contenido_se_completa_al_abrir(contenido):
        doc = (progreso or {}).get(clave_contenido(contenido)) or {}
        return bool(doc.get("completado"))
    doc = (progreso or {}).get(clave_contenido(contenido)) or {}
    return bool(doc.get("completado"))


def estado_secuencial(codigo_evento, cedula, contenidos):
    """Completitud de los contenidos navegables y el primer pendiente.

    Devuelve (completados, primer_pendiente): `completados` es un dict
    clave_contenido -> bool y `primer_pendiente` el doc del primer contenido
    no completado en orden, o None si ya completó todo.
    """
    progreso = _progreso_del_participante(codigo_evento, cedula)
    completados = {}
    primer_pendiente = None
    for contenido in contenidos:
        if not es_navegable(contenido):
            continue
        completado = contenido_completado(codigo_evento, cedula, contenido, progreso)
        completados[clave_contenido(contenido)] = completado
        if not completado and primer_pendiente is None:
            primer_pendiente = contenido
    return completados, primer_pendiente


def marcar_contenido_visto(codigo_evento, cedula, contenido, porcentaje=100):
    """Registra un contenido como completado al abrirlo."""
    ahora = datetime.now()
    collection_progreso.update_one(
        {
            "codigo_evento": codigo_evento,
            "cedula_participante": str(cedula),
            "contenido_id": clave_contenido(contenido),
        },
        {
            "$set": {
                "orden": contenido.get("orden"),
                "tipo": contenido.get("tipo"),
                "completado": True,
                "fecha_actualizacion": ahora,
            },
            "$setOnInsert": {"fecha_inicio": ahora, "fecha_completado": ahora},
            "$max": {"porcentaje": int(porcentaje)},
        },
        upsert=True,
    )


def registrar_progreso_video(codigo_evento, cedula, contenido, delta, duracion):
    """Acumula segundos reproducidos de un video y evalúa el umbral del 50%.

    El cliente informa solo el tiempo nuevo reproducido (`delta`). El servidor
    acumula entre sesiones y exige haber visto la mitad del video. Devuelve
    (porcentaje, completado).
    """
    filtro = {
        "codigo_evento": codigo_evento,
        "cedula_participante": str(cedula),
        "contenido_id": clave_contenido(contenido),
    }
    doc = collection_progreso.find_one(filtro) or {}
    segundos = float(doc.get("segundos_vistos") or 0)
    if segundos > duracion:
        # El contenido cambió de duración: el acumulado anterior ya no sirve.
        segundos = 0
    segundos = min(duracion, segundos + delta)
    porcentaje = int(round(segundos * 100 / duracion))
    completado = bool(doc.get("completado")) or porcentaje >= UMBRAL_VIDEO_PORCENTAJE
    ahora = datetime.now()
    actualizacion = {
        "$set": {
            "orden": contenido.get("orden"),
            "tipo": "video",
            "segundos_vistos": segundos,
            "duracion": duracion,
            "porcentaje": porcentaje,
            "completado": completado,
            "fecha_actualizacion": ahora,
        },
        "$setOnInsert": {"fecha_inicio": ahora},
    }
    if completado and not doc.get("completado"):
        actualizacion["$set"]["fecha_completado"] = ahora
    collection_progreso.update_one(filtro, actualizacion, upsert=True)
    return porcentaje, completado


def _bloquear_reorden_si_hay_historicos(codigo_evento, accion):
    """Impide cambiar órdenes si hay calificaciones que dependen de ellos.

    Los registros históricos sin examen_id/tarea_id se resuelven por orden;
    cambiarlo los desalinearía. Hasta que se enlacen por id, no se permite
    reordenar.
    """
    examenes, tareas = contar_sin_enlace(codigo_evento)
    if not examenes and not tareas:
        return False
    flash(
        f"No se puede {accion}: este evento tiene {examenes} intento(s) de "
        f"examen y {tareas} entrega(s) sin enlace estable por id. Ejecuta "
        "scripts/backfill_lms_fks.py para este evento y vuelve a intentarlo.",
        "error",
    )
    return True


def estado_tareas_evento(codigo_evento, cedula_participante):
    """Tareas manuales del evento y entrega de un participante por tarea.

    Retorna (tareas, por_tarea) donde por_tarea[tarea_id_str] es el doc de
    entrega/calificación o None. El match es por tarea_id estable con
    fallback a orden_tarea para históricos.
    """
    tareas = list(
        collection_eva.find(
            {"codigo_evento": codigo_evento, "tipo": "tarea"}
        ).sort("orden", 1)
    )
    if not tareas or not cedula_participante:
        return tareas, {}
    ids = [_id_str(t) for t in tareas]
    ordenes = [t.get("orden") for t in tareas]
    entregas = list(
        collection_tarea_entregas.find(
            {
                "codigo_evento": codigo_evento,
                "cedula_participante": cedula_participante,
                "$or": [
                    {"tarea_id": {"$in": ids}},
                    {"tarea_id": None, "orden_tarea": {"$in": ordenes}},
                    {
                        "tarea_id": {"$exists": False},
                        "orden_tarea": {"$in": ordenes},
                    },
                ],
            }
        )
    )
    por_tarea = {}
    for t in tareas:
        tid = _id_str(t)
        match = next(
            (
                e
                for e in entregas
                if e.get("tarea_id") and str(e.get("tarea_id")) == tid
            ),
            None,
        )
        if match is None:
            match = next(
                (
                    e
                    for e in entregas
                    if not e.get("tarea_id")
                    and e.get("orden_tarea") == t.get("orden")
                ),
                None,
            )
        por_tarea[tid] = match
    return tareas, por_tarea


def progreso_lms(codigo_evento, cedula_participante, evento):
    """Progreso combinado de sumativas + tareas manuales (umbral 80).

    Las tareas manuales cuentan igual que los exámenes sumativos para el
    certificado: todas deben estar aprobadas con >=80.
    """
    res = {
        "total_sumativos": 0,
        "aprobados_sumativos": 0,
        "total_tareas": 0,
        "aprobadas_tareas": 0,
        "todos_aprobados": False,
        "encuesta_completada": False,
        "certificado_disponible": False,
    }
    if not cedula_participante:
        return res
    examenes = list(
        collection_eva.find(
            {"codigo_evento": codigo_evento, "tipo": "examen"}
        )
    )
    sumativos = [
        ex
        for ex in examenes
        if ex.get("qbank_config")
        and not parse_qbank_config(ex.get("qbank_config", ""))[3]
    ]
    res["total_sumativos"] = len(sumativos)
    if sumativos:
        ids_sum = [_id_str(ex) for ex in sumativos]
        ords_sum = [ex.get("orden") for ex in sumativos]
        resultados = list(
            collection_exam_results.find(
                {
                    "codigo_evento": codigo_evento,
                    "cedula_participante": cedula_participante,
                    "$or": [
                        {"examen_id": {"$in": ids_sum}},
                        {
                            "examen_id": None,
                            "orden_examen": {"$in": ords_sum},
                        },
                        {
                            "examen_id": {"$exists": False},
                            "orden_examen": {"$in": ords_sum},
                        },
                    ],
                }
            )
        )
        for ex in sumativos:
            mejor = mejor_resultado_examen(resultados, ex)
            if mejor and mejor.get("calificacion", 0) >= UMBRAL_APROBACION:
                res["aprobados_sumativos"] += 1
    tareas, por_tarea = estado_tareas_evento(codigo_evento, cedula_participante)
    res["total_tareas"] = len(tareas)
    for t in tareas:
        ent = por_tarea.get(_id_str(t))
        if (
            ent
            and ent.get("calificacion") is not None
            and ent.get("calificacion", 0) >= UMBRAL_APROBACION
        ):
            res["aprobadas_tareas"] += 1
    res["todos_aprobados"] = (
        res["aprobados_sumativos"] == res["total_sumativos"]
        and res["aprobadas_tareas"] == res["total_tareas"]
    )
    from app.verifica_encuesta import (
        requires_survey_completion,
        has_completed_survey_v2,
    )

    if requires_survey_completion(evento):
        res["encuesta_completada"] = has_completed_survey_v2(
            cedula_participante, codigo_evento
        )
    else:
        res["encuesta_completada"] = True
    res["certificado_disponible"] = (
        res["todos_aprobados"] and res["encuesta_completada"]
    )
    return res


def mejor_resultado_examen(resultados, examen):
    """Mejor intento para un examen, con fallback para históricos.

    Los resultados nuevos guardan `examen_id` (FK estable ante
    reordenamientos). Los históricos solo tienen `orden_examen`, que es
    mutable (mover/eliminar renumeran). Se prefiere `examen_id` y se cae
    a `orden_examen` solo para docs sin `examen_id`.
    """
    eid = _id_str(examen)
    cands = [
        r for r in resultados
        if r.get("examen_id") and str(r.get("examen_id")) == eid
    ]
    if not cands:
        cands = [
            r for r in resultados
            if not r.get("examen_id") and r.get("orden_examen") == examen.get("orden")
        ]
    return max(cands, key=lambda r: r.get("calificacion", 0), default=None)


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
    actividades = list(actividades)
    arbol = build_arbol_lms(actividades)

    return render_template(
        "listar_contenido.html",
        codigo_evento=codigo_evento,
        evento=evento,
        actividades=actividades,
        arbol=arbol,
    )


@plataforma_bp.route(
    "/tablero/eventos/<codigo_evento>/lms/secuencial", methods=["POST"]
)
@login_required
@lms_required
def configurar_secuencial(codigo_evento):
    """Activa o desactiva el avance secuencial del curso."""
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)

    activo = request.form.get("lms_secuencial") == "1"
    collection_eventos.update_one(
        {"codigo": codigo_evento}, {"$set": {"lms_secuencial": activo}}
    )
    if activo:
        flash(
            "Avance secuencial activado: cada participante deberá completar un "
            "contenido antes de abrir el siguiente.",
            "success",
        )
    else:
        flash("Avance secuencial desactivado.", "success")
    return redirect(
        url_for("plataforma.listar_contenidos", codigo_evento=codigo_evento)
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
        modulo_id = (request.form.get("modulo_id") or "").strip() or None
        submodulo_id = (request.form.get("submodulo_id") or "").strip() or None

        # Obtener el próximo número en la secuencia
        ultimo_contenido = collection_eva.find_one(
            {"codigo_evento": codigo_evento}, sort=[("orden", -1)]
        )
        nuevo_orden = (ultimo_contenido["orden"] + 1) if ultimo_contenido else 1

        # Posición elegida: al final (por defecto) o después de un contenido.
        posicion = (request.form.get("posicion") or "final").strip()
        posicion_destino = None
        if posicion.startswith("despues:"):
            try:
                posicion_destino = int(posicion.split(":", 1)[1])
            except (TypeError, ValueError):
                posicion_destino = None
            if posicion_destino is None or not collection_eva.find_one(
                {"codigo_evento": codigo_evento, "orden": posicion_destino}
            ):
                flash("La posición seleccionada ya no existe.", "error")
                return redirect(request.url)
            if _bloquear_reorden_si_hay_historicos(
                codigo_evento, "insertar en una posición"
            ):
                return redirect(request.url)
            nuevo_orden = posicion_destino + 1

        contenido = {
            "codigo_evento": codigo_evento,
            "orden": nuevo_orden,
            "titulo": titulo,
            "descripcion": descripcion,
            "tipo": tipo,
            "modulo_id": None,
            "submodulo_id": None,
        }

        if tipo == "submodulo":
            # Submódulo: requiere módulo padre, sin padre propio adicional.
            if not modulo_id:
                flash("El submódulo requiere un módulo padre.", "error")
                return redirect(request.url)
            padre = collection_eva.find_one(
                {"codigo_evento": codigo_evento, "tipo": "modulo"}
            )
            # Validar que el id corresponda a un módulo del evento
            try:
                padre = collection_eva.find_one(
                    {"_id": ObjectId(modulo_id), "codigo_evento": codigo_evento}
                )
            except Exception:
                padre = None
            if not padre or padre.get("tipo") != "modulo":
                flash("El módulo padre seleccionado no es válido.", "error")
                return redirect(request.url)
            contenido["modulo_id"] = str(padre["_id"])
        elif tipo not in TIPOS_NO_NAVEGABLES:
            # Contenido navegable: padres opcionales (modo mixto permite huérfanos)
            if modulo_id:
                try:
                    padre = collection_eva.find_one(
                        {"_id": ObjectId(modulo_id), "codigo_evento": codigo_evento}
                    )
                except Exception:
                    padre = None
                if not padre or padre.get("tipo") != "modulo":
                    flash("El módulo padre seleccionado no es válido.", "error")
                    return redirect(request.url)
                contenido["modulo_id"] = str(padre["_id"])
            if submodulo_id:
                try:
                    sub = collection_eva.find_one(
                        {"_id": ObjectId(submodulo_id), "codigo_evento": codigo_evento}
                    )
                except Exception:
                    sub = None
                if not sub or sub.get("tipo") != "submodulo":
                    flash("El submódulo padre seleccionado no es válido.", "error")
                    return redirect(request.url)
                # Coherencia: el submódulo debe colgar del mismo módulo
                sub_mid = str(sub.get("modulo_id")) if sub.get("modulo_id") else None
                if contenido["modulo_id"] and sub_mid != contenido["modulo_id"]:
                    flash("El submódulo no pertenece al módulo seleccionado.", "error")
                    return redirect(request.url)
                if not contenido["modulo_id"] and sub_mid:
                    contenido["modulo_id"] = sub_mid
                contenido["submodulo_id"] = str(sub["_id"])

        if tipo == "video":
            contenido["url_video"] = request.form["url_video"]
            try:
                material_pdf, material_pdf_nombre = guardar_material_pdf(
                    request.files.get("material_pdf"), codigo_evento
                )
            except ValueError as error:
                flash(str(error), "error")
                return redirect(request.url)
            if material_pdf:
                contenido["material_pdf"] = material_pdf
                contenido["material_pdf_nombre"] = material_pdf_nombre

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
                documento_filename = f"documento-{codigo_evento}-{uuid.uuid4().hex[:8]}{extension}"
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

        elif tipo == "tarea":
            contenido["requiere_entrega"] = request.form.get("requiere_entrega") == "si"
            contenido["permite_archivo"] = request.form.get("permite_archivo") == "si"
            contenido["instrucciones"] = request.form.get("instrucciones", "").strip()

        elif tipo == "modulo":
            # Módulo organizador: separador visual sin campos propios.
            # Solo guarda titulo + descripcion, no es navegable.
            pass

        elif tipo == "submodulo":
            # Submódulo organizador: igual que módulo pero colgado de un padre.
            pass

        if posicion_destino is not None:
            # Desplazar los posteriores solo cuando el contenido ya es válido.
            collection_eva.update_many(
                {
                    "codigo_evento": codigo_evento,
                    "orden": {"$gte": nuevo_orden},
                },
                {"$inc": {"orden": 1}},
            )

        collection_eva.insert_one(contenido)

        return redirect(
            url_for("plataforma.listar_contenidos", codigo_evento=codigo_evento)
        )

    modulos = list(
        collection_eva.find({"codigo_evento": codigo_evento, "tipo": "modulo"}).sort("orden", 1)
    )
    submodulos = list(
        collection_eva.find({"codigo_evento": codigo_evento, "tipo": "submodulo"}).sort("orden", 1)
    )
    return render_template(
        "crear_contenido.html",
        evento=evento,
        modulos=modulos,
        submodulos=submodulos,
        actividades=list(
            collection_eva.find({"codigo_evento": codigo_evento}).sort("orden", 1)
        ),
    )


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
        modulo_id = (request.form.get("modulo_id") or "").strip() or None
        submodulo_id = (request.form.get("submodulo_id") or "").strip() or None
        tipo_anterior = contenido.get("tipo")

        # Proteger calificaciones: no convertir un examen o tarea con
        # calificaciones/entregas en módulo/submódulo (dejaría resultados
        # huérfanos).
        if tipo_anterior == "examen" and tipo in TIPOS_NO_NAVEGABLES:
            intentos = collection_exam_results.count_documents(
                {
                    "codigo_evento": codigo_evento,
                    "orden_examen": orden,
                }
            )
            if intentos > 0:
                flash(
                    "No se puede convertir un examen con intentos registrados en "
                    "módulo/submódulo porque se perdería la trazabilidad de calificaciones.",
                    "error",
                )
                return redirect(request.url)
        if tipo_anterior == "tarea" and tipo in TIPOS_NO_NAVEGABLES:
            entregas = collection_tarea_entregas.count_documents(
                {
                    "codigo_evento": codigo_evento,
                    "orden_tarea": orden,
                }
            )
            if entregas > 0:
                flash(
                    "No se puede convertir una tarea con entregas o calificaciones "
                    "en módulo/submódulo porque se perdería la trazabilidad.",
                    "error",
                )
                return redirect(request.url)

        actualizacion = {
            "titulo": titulo,
            "descripcion": descripcion,
            "tipo": tipo,
            "modulo_id": None,
            "submodulo_id": None,
        }

        if tipo == "submodulo":
            if not modulo_id:
                flash("El submódulo requiere un módulo padre.", "error")
                return redirect(request.url)
            try:
                padre = collection_eva.find_one(
                    {"_id": ObjectId(modulo_id), "codigo_evento": codigo_evento}
                )
            except Exception:
                padre = None
            if not padre or padre.get("tipo") != "modulo":
                flash("El módulo padre seleccionado no es válido.", "error")
                return redirect(request.url)
            if _id_str(contenido) and modulo_id == _id_str(contenido):
                flash("Un submódulo no puede ser su propio padre.", "error")
                return redirect(request.url)
            actualizacion["modulo_id"] = str(padre["_id"])
        elif tipo not in TIPOS_NO_NAVEGABLES:
            if modulo_id:
                try:
                    padre = collection_eva.find_one(
                        {"_id": ObjectId(modulo_id), "codigo_evento": codigo_evento}
                    )
                except Exception:
                    padre = None
                if not padre or padre.get("tipo") != "modulo":
                    flash("El módulo padre seleccionado no es válido.", "error")
                    return redirect(request.url)
                actualizacion["modulo_id"] = str(padre["_id"])
            if submodulo_id:
                try:
                    sub = collection_eva.find_one(
                        {"_id": ObjectId(submodulo_id), "codigo_evento": codigo_evento}
                    )
                except Exception:
                    sub = None
                if not sub or sub.get("tipo") != "submodulo":
                    flash("El submódulo padre seleccionado no es válido.", "error")
                    return redirect(request.url)
                sub_mid = str(sub.get("modulo_id")) if sub.get("modulo_id") else None
                if actualizacion["modulo_id"] and sub_mid != actualizacion["modulo_id"]:
                    flash("El submódulo no pertenece al módulo seleccionado.", "error")
                    return redirect(request.url)
                if not actualizacion["modulo_id"] and sub_mid:
                    actualizacion["modulo_id"] = sub_mid
                actualizacion["submodulo_id"] = str(sub["_id"])

        if tipo == "video":
            actualizacion["url_video"] = request.form["url_video"]
            if request.form.get("eliminar_material_pdf") == "1":
                actualizacion["material_pdf"] = ""
                actualizacion["material_pdf_nombre"] = ""
            try:
                material_pdf, material_pdf_nombre = guardar_material_pdf(
                    request.files.get("material_pdf"), codigo_evento
                )
            except ValueError as error:
                flash(str(error), "error")
                return redirect(request.url)
            if material_pdf:
                actualizacion["material_pdf"] = material_pdf
                actualizacion["material_pdf_nombre"] = material_pdf_nombre
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
                documento_filename = f"documento-{codigo_evento}-{uuid.uuid4().hex[:8]}{extension}"
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
        elif tipo == "tarea":
            actualizacion["requiere_entrega"] = request.form.get("requiere_entrega") == "si"
            actualizacion["permite_archivo"] = request.form.get("permite_archivo") == "si"
            actualizacion["instrucciones"] = request.form.get("instrucciones", "").strip()
        elif tipo == "modulo":
            # Módulo organizador: sin campos propios.
            pass
        elif tipo == "submodulo":
            # Submódulo organizador: sin campos propios.
            pass

        # Campos específicos por tipo: al cambiar de tipo se eliminan los
        # campos huérfanos del tipo anterior para no arrastrar basura.
        campos_por_tipo = {
            "video": {"url_video", "material_pdf", "material_pdf_nombre"},
            "texto": {"contenido_texto"},
            "documento": {"documento"},
            "caso_chatgpt": {"contenido_json"},
            "examen": {"qbank_config"},
            "tarea": {"requiere_entrega", "permite_archivo", "instrucciones"},
            "modulo": set(),
            "submodulo": set(),
        }
        todos_los_campos = set().union(*campos_por_tipo.values())
        campos_a_conservar = campos_por_tipo.get(tipo, set())
        campos_a_limpiar = {
            campo: "" for campo in (todos_los_campos - campos_a_conservar)
        }

        collection_eva.update_one(
            {"codigo_evento": codigo_evento, "orden": orden}, {"$set": actualizacion}
        )
        if campos_a_limpiar:
            collection_eva.update_one(
                {"codigo_evento": codigo_evento, "orden": orden},
                {"$unset": campos_a_limpiar},
            )

        return redirect(
            url_for("plataforma.listar_contenidos", codigo_evento=codigo_evento)
        )

    modulos = list(
        collection_eva.find({"codigo_evento": codigo_evento, "tipo": "modulo"}).sort("orden", 1)
    )
    submodulos = list(
        collection_eva.find({"codigo_evento": codigo_evento, "tipo": "submodulo"}).sort("orden", 1)
    )
    return render_template(
        "editar_contenido.html",
        evento=evento,
        contenido=contenido,
        modulos=modulos,
        submodulos=submodulos,
    )


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
    arbol = build_arbol_lms(contenidos)
    contenidos_by_id = {_id_str(c): c for c in contenidos}
    modulo_padre, submodulo_padre = breadcrumb_lms(contenidos_by_id, contenido)

    # Convertir Markdown a HTML solo si el tipo es 'texto'
    import markdown

    if contenido.get("tipo") == "texto" and "contenido_texto" in contenido:
        contenido["contenido_texto"] = markdown.markdown(contenido["contenido_texto"])

    # Si es examen, cargar las preguntas para la previsualización
    preguntas = []
    if contenido.get("tipo") == "examen" and "qbank_config" in contenido:
        codigo_qbank, num_preguntas, aleatorio, formativo, persistencia, evaluable = parse_qbank_config(
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
        arbol=arbol,
        modulo_padre=modulo_padre,
        submodulo_padre=submodulo_padre,
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

    if _bloquear_reorden_si_hay_historicos(codigo_evento, "mover contenidos"):
        return redirect(
            url_for("plataforma.listar_contenidos", codigo_evento=codigo_evento)
        )

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

    # Avisar si se movió un examen o tarea con calificaciones: se conservan
    # por examen_id/tarea_id, pero conviene verificar el listado interno.
    for movido in (contenido_actual, contenido_destino):
        if movido.get("tipo") == "examen":
            n = collection_exam_results.count_documents(
                {
                    "codigo_evento": codigo_evento,
                    "$or": [
                        {"examen_id": _id_str(movido)},
                        {
                            "examen_id": {"$in": [None]},
                            "orden_examen": movido.get("orden"),
                        },
                    ],
                }
            )
            if n > 0:
                flash(
                    f"«{movido.get('titulo', 'Examen')}» tiene {n} intento(s) registrado(s). "
                    "Se movió conservando calificaciones (enlace por examen_id); "
                    "verifica el listado de calificaciones.",
                    "info",
                )
                break
        elif movido.get("tipo") == "tarea":
            n = collection_tarea_entregas.count_documents(
                {
                    "codigo_evento": codigo_evento,
                    "$or": [
                        {"tarea_id": _id_str(movido)},
                        {
                            "tarea_id": {"$in": [None]},
                            "orden_tarea": movido.get("orden"),
                        },
                    ],
                }
            )
            if n > 0:
                flash(
                    f"«{movido.get('titulo', 'Tarea')}» tiene {n} entrega(s)/calificación(es) registrada(s). "
                    "Se movió conservando calificaciones (enlace por tarea_id); "
                    "verifica el listado de calificaciones.",
                    "info",
                )
                break

    return redirect(
        url_for("plataforma.listar_contenidos", codigo_evento=codigo_evento)
    )


@plataforma_bp.route(
    "/tablero/eventos/<codigo_evento>/lms/reordenar", methods=["POST"]
)
@login_required
@lms_required
def reordenar_contenidos(codigo_evento):
    """Mueve un contenido a una posición elegida sin flechas una por una."""
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)

    destino_lista = url_for(
        "plataforma.listar_contenidos", codigo_evento=codigo_evento
    )

    if _bloquear_reorden_si_hay_historicos(codigo_evento, "reordenar contenidos"):
        return redirect(destino_lista)

    try:
        mover_orden = int(request.form.get("mover_orden", ""))
    except (TypeError, ValueError):
        flash("Selecciona el contenido que quieres mover.", "error")
        return redirect(destino_lista)

    destino = (request.form.get("destino") or "").strip()
    contenidos = list(
        collection_eva.find({"codigo_evento": codigo_evento}).sort("orden", 1)
    )
    actual = next((c for c in contenidos if c.get("orden") == mover_orden), None)
    if not actual:
        flash("El contenido a mover ya no existe.", "error")
        return redirect(destino_lista)

    minimo = contenidos[0]["orden"] if contenidos else 1
    maximo = contenidos[-1]["orden"] if contenidos else 0

    if destino == "inicio":
        if actual["orden"] == minimo:
            return redirect(destino_lista)
        if minimo > 1:
            collection_eva.update_one(
                {"_id": actual["_id"]}, {"$set": {"orden": minimo - 1}}
            )
        else:
            collection_eva.update_many(
                {"codigo_evento": codigo_evento}, {"$inc": {"orden": 1}}
            )
            collection_eva.update_one(
                {"_id": actual["_id"]}, {"$set": {"orden": 1}}
            )
    elif destino == "final":
        if actual["orden"] == maximo:
            return redirect(destino_lista)
        collection_eva.update_one(
            {"_id": actual["_id"]}, {"$set": {"orden": maximo + 1}}
        )
    elif destino.startswith("despues:"):
        try:
            destino_orden = int(destino.split(":", 1)[1])
        except (TypeError, ValueError):
            destino_orden = None
        destino_doc = next(
            (c for c in contenidos if c.get("orden") == destino_orden), None
        )
        if destino_doc is None:
            flash("La posición de destino ya no existe.", "error")
            return redirect(destino_lista)
        if destino_doc["_id"] == actual["_id"]:
            flash("No puedes mover un contenido después de sí mismo.", "error")
            return redirect(destino_lista)
        if actual["orden"] < destino_orden:
            # Bajar: el destino y los intermedios suben un puesto.
            collection_eva.update_many(
                {
                    "codigo_evento": codigo_evento,
                    "orden": {"$gt": actual["orden"], "$lte": destino_orden},
                },
                {"$inc": {"orden": -1}},
            )
            collection_eva.update_one(
                {"_id": actual["_id"]}, {"$set": {"orden": destino_orden}}
            )
        elif actual["orden"] > destino_orden:
            # Subir: los intermedios bajan un puesto.
            collection_eva.update_many(
                {
                    "codigo_evento": codigo_evento,
                    "orden": {"$gt": destino_orden, "$lt": actual["orden"]},
                },
                {"$inc": {"orden": 1}},
            )
            collection_eva.update_one(
                {"_id": actual["_id"]}, {"$set": {"orden": destino_orden + 1}}
            )
        else:
            return redirect(destino_lista)
    else:
        flash("Selecciona una posición de destino.", "error")
        return redirect(destino_lista)

    flash("Contenido reordenado.", "success")
    return redirect(destino_lista)


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

    contenido_id = _id_str(contenido)
    # Proteger jerarquía: no eliminar módulo/submódulo con hijos sin reasignar.
    if contenido.get("tipo") == "modulo":
        hijos = collection_eva.count_documents(
            {"codigo_evento": codigo_evento, "modulo_id": contenido_id}
        )
        if hijos > 0:
            flash(
                f"No se puede eliminar el módulo: tiene {hijos} elemento(s) asignado(s). "
                "Reasigna o elimina primero sus submódulos y contenidos.",
                "error",
            )
            return redirect(
                url_for("plataforma.listar_contenidos", codigo_evento=codigo_evento)
            )
    elif contenido.get("tipo") == "submodulo":
        hijos = collection_eva.count_documents(
            {"codigo_evento": codigo_evento, "submodulo_id": contenido_id}
        )
        if hijos > 0:
            flash(
                f"No se puede eliminar el submódulo: tiene {hijos} contenido(s) asignado(s). "
                "Reasigna o elimina primero sus contenidos.",
                "error",
            )
            return redirect(
                url_for("plataforma.listar_contenidos", codigo_evento=codigo_evento)
            )

    collection_eva.delete_one({"codigo_evento": codigo_evento, "orden": orden})

    # Reordenar los elementos después de la eliminación
    contenidos_restantes = list(
        collection_eva.find({"codigo_evento": codigo_evento}).sort("orden", 1)
    )
    for i, cont in enumerate(contenidos_restantes, start=1):
        collection_eva.update_one({"_id": cont["_id"]}, {"$set": {"orden": i}})

    if contenido.get("tipo") == "examen":
        n = collection_exam_results.count_documents(
            {
                "codigo_evento": codigo_evento,
                "$or": [
                    {"examen_id": contenido_id},
                    {"examen_id": {"$in": [None]}, "orden_examen": orden},
                ],
            }
        )
        if n > 0:
            flash(
                f"Se eliminó un examen con {n} intento(s) registrado(s) y se renumeró "
                "el resto. Las calificaciones históricas se conservan por examen_id; "
                "verifica el listado de calificaciones.",
                "info",
            )

    if contenido.get("tipo") == "tarea":
        n = collection_tarea_entregas.count_documents(
            {
                "codigo_evento": codigo_evento,
                "$or": [
                    {"tarea_id": contenido_id},
                    {"tarea_id": {"$in": [None]}, "orden_tarea": orden},
                ],
            }
        )
        if n > 0:
            flash(
                f"Se eliminó una tarea con {n} entrega(s)/calificación(es) registrada(s) "
                "y se renumeró el resto. Los registros históricos se conservan por "
                "tarea_id; verifica el listado de calificaciones.",
                "info",
            )

    return redirect(
        url_for("plataforma.listar_contenidos", codigo_evento=codigo_evento)
    )


###
### LMS - Calificar tarea manual (autor / coorganizador con cuenta / admin-denadoi)
###
@plataforma_bp.route(
    "/tablero/eventos/<codigo_evento>/lms/<int:orden>/calificar",
    methods=["GET"],
)
@login_required
@lms_required
def calificar_tarea(codigo_evento, orden):
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)
    contenido = collection_eva.find_one(
        {"codigo_evento": codigo_evento, "orden": orden}
    )
    if not contenido or contenido.get("tipo") != "tarea":
        abort(404)
    if not puede_calificar_evento(evento):
        abort(403)

    tarea_id = _id_str(contenido)
    participantes = list(
        collection_participantes.find(
            {"codigo_evento": codigo_evento, "rol": "participante"}
        ).sort([("apellidos", 1), ("nombres", 1)])
    )
    entregas = {
        e.get("cedula_participante"): e
        for e in collection_tarea_entregas.find(
            {
                "codigo_evento": codigo_evento,
                "$or": [
                    {"tarea_id": tarea_id},
                    {"tarea_id": None, "orden_tarea": orden},
                    {"tarea_id": {"$exists": False}, "orden_tarea": orden},
                ],
            }
        )
    }
    filtro = (request.args.get("filtro") or "todos").strip()
    if filtro not in ("todos", "pendientes", "calificados"):
        filtro = "todos"
    q = (request.args.get("q") or "").strip().lower()
    filas = []
    for p in participantes:
        ent = entregas.get(p.get("cedula"))
        calif = ent.get("calificacion") if ent else None
        estado = (
            "calificado"
            if (calif is not None)
            else ("entregado" if ent else "sin_entrega")
        )
        if filtro == "pendientes" and estado == "calificado":
            continue
        if filtro == "calificados" and estado != "calificado":
            continue
        if q and q not in (
            f"{p.get('nombres', '')} {p.get('apellidos', '')} "
            f"{p.get('cedula', '')}".lower()
        ):
            continue
        filas.append({"participante": p, "entrega": ent, "estado": estado})

    return render_template(
        "calificar_tarea.html",
        evento=evento,
        contenido=contenido,
        filas=filas,
        filtro=filtro,
        q=request.args.get("q", ""),
    )


@plataforma_bp.route(
    "/tablero/eventos/<codigo_evento>/lms/<int:orden>/calificar/<cedula>",
    methods=["POST"],
)
@login_required
@lms_required
def guardar_calificacion_tarea(codigo_evento, orden, cedula):
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)
    contenido = collection_eva.find_one(
        {"codigo_evento": codigo_evento, "orden": orden}
    )
    if not contenido or contenido.get("tipo") != "tarea":
        abort(404)
    if not puede_calificar_evento(evento):
        abort(403)

    nota_raw = (request.form.get("calificacion") or "").strip().replace(",", ".")
    try:
        calificacion = float(nota_raw)
    except (TypeError, ValueError):
        flash("La calificación debe ser un número entre 0 y 100.", "error")
        return redirect(
            url_for(
                "plataforma.calificar_tarea",
                codigo_evento=codigo_evento,
                orden=orden,
            )
        )
    if calificacion < 0 or calificacion > 100:
        flash("La calificación debe estar entre 0 y 100.", "error")
        return redirect(
            url_for(
                "plataforma.calificar_tarea",
                codigo_evento=codigo_evento,
                orden=orden,
            )
        )
    feedback = (request.form.get("feedback") or "").strip()[:2000]
    tarea_id = _id_str(contenido)
    entrega = collection_tarea_entregas.find_one(
        {
            "codigo_evento": codigo_evento,
            "cedula_participante": cedula,
            "$or": [
                {"tarea_id": tarea_id},
                {"tarea_id": None, "orden_tarea": orden},
                {"tarea_id": {"$exists": False}, "orden_tarea": orden},
            ],
        }
    )
    ahora = datetime.now()
    datos = {
        "tarea_id": tarea_id,
        "orden_tarea": orden,
        "calificacion": round(calificacion, 1),
        "feedback": feedback,
        "estado": "calificado",
        "calificado_por": getattr(current_user, "id", None),
        "fecha_calificacion": ahora,
        "titulo_tarea": contenido.get("titulo", "Sin título"),
        "titulo_evento": evento.get("titulo", "Sin título"),
    }
    if entrega:
        collection_tarea_entregas.update_one(
            {"_id": entrega["_id"]}, {"$set": datos}
        )
    else:
        # Calificación directa sin entrega previa (tarea sin entrega
        # requerida o participante calificado de oficio).
        datos.update(
            {
                "codigo_evento": codigo_evento,
                "cedula_participante": cedula,
                "texto_entrega": "",
                "archivo_path": None,
                "fecha_entrega": None,
            }
        )
        collection_tarea_entregas.insert_one(datos)
    flash(f"Calificación guardada para {cedula}.", "success")
    return redirect(
        url_for(
            "plataforma.calificar_tarea",
            codigo_evento=codigo_evento,
            orden=orden,
            filtro=request.form.get("filtro", "todos"),
            q=request.form.get("q", ""),
        )
    )


###
### LMS - Copiar contenidos a otro evento
###
@plataforma_bp.route("/tablero/eventos/<codigo_evento>/lms/copiar", methods=["GET", "POST"])
@login_required
@lms_required
def copiar_lms(codigo_evento):
    evento_origen = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento_origen:
        abort(404)

    if request.method == "POST":
        codigo_destino = request.form.get("codigo_destino").strip()
        
        evento_destino = collection_eventos.find_one({"codigo": codigo_destino})
        if not evento_destino:
            flash("El evento destino no existe", "danger")
            return redirect(url_for("plataforma.copiar_lms", codigo_evento=codigo_evento))
        
        contenidos = list(collection_eva.find({"codigo_evento": codigo_evento}).sort("orden", 1))
        
        if not contenidos:
            flash("No hay contenidos LMS para copiar", "warning")
            return redirect(url_for("ver_evento", codigo_evento=codigo_evento))
        
        # Verificar que el evento destino sea virtual/tenga modalidad no presencial
        if not evento_destino.get("lms_activo", evento_destino.get("modalidad") != "Presencial"):
            flash("No se puede copiar LMS a un evento presencial", "danger")
            return redirect(url_for("plataforma.copiar_lms", codigo_evento=codigo_evento))
        
        upload_folder = current_app.config["UPLOAD_FOLDER"]

        # Copia en 3 pasadas para preservar jerarquía: módulos -> submódulos
        # -> contenidos. Se mapean _id origen (str) a _id destino (str).
        id_map = {}
        for contenido in contenidos:
            if contenido.get("tipo") != "modulo":
                continue
            nuevo_contenido = {
                "codigo_evento": codigo_destino,
                "orden": contenido["orden"],
                "titulo": contenido.get("titulo", ""),
                "descripcion": contenido.get("descripcion", ""),
                "tipo": "modulo",
                "modulo_id": None,
                "submodulo_id": None,
            }
            res = collection_eva.insert_one(nuevo_contenido)
            id_map[str(contenido["_id"])] = str(res.inserted_id)

        for contenido in contenidos:
            if contenido.get("tipo") != "submodulo":
                continue
            old_mid = str(contenido.get("modulo_id")) if contenido.get("modulo_id") else None
            nuevo_contenido = {
                "codigo_evento": codigo_destino,
                "orden": contenido["orden"],
                "titulo": contenido.get("titulo", ""),
                "descripcion": contenido.get("descripcion", ""),
                "tipo": "submodulo",
                "modulo_id": id_map.get(old_mid) if old_mid else None,
                "submodulo_id": None,
            }
            res = collection_eva.insert_one(nuevo_contenido)
            id_map[str(contenido["_id"])] = str(res.inserted_id)

        for contenido in contenidos:
            if contenido.get("tipo") in ("modulo", "submodulo"):
                continue
            nuevo_orden = contenido["orden"]

            old_mid = str(contenido.get("modulo_id")) if contenido.get("modulo_id") else None
            old_sid = str(contenido.get("submodulo_id")) if contenido.get("submodulo_id") else None
            nuevo_contenido = {
                "codigo_evento": codigo_destino,
                "orden": nuevo_orden,
                "titulo": contenido.get("titulo", ""),
                "descripcion": contenido.get("descripcion", ""),
                "tipo": contenido.get("tipo", ""),
                "modulo_id": id_map.get(old_mid) if old_mid else None,
                "submodulo_id": id_map.get(old_sid) if old_sid else None,
            }
            
            if contenido.get("tipo") == "video":
                nuevo_contenido["url_video"] = contenido.get("url_video", "")
                if contenido.get("material_pdf"):
                    import shutil

                    old_material = contenido["material_pdf"]
                    old_material_path = os.path.join(
                        upload_folder, old_material
                    )
                    if os.path.exists(old_material_path):
                        evento_folder_destino = os.path.join(
                            upload_folder, codigo_destino
                        )
                        os.makedirs(evento_folder_destino, exist_ok=True)
                        new_material = (
                            f"presentacion-{codigo_destino}-{uuid.uuid4().hex[:8]}.pdf"
                        )
                        shutil.copy2(
                            old_material_path,
                            os.path.join(evento_folder_destino, new_material),
                        )
                        nuevo_contenido["material_pdf"] = (
                            f"{codigo_destino}/{new_material}"
                        )
                        nuevo_contenido["material_pdf_nombre"] = contenido.get(
                            "material_pdf_nombre", ""
                        )
            
            elif contenido.get("tipo") == "texto":
                nuevo_contenido["contenido_texto"] = contenido.get("contenido_texto", "")
            
            elif contenido.get("tipo") == "documento":
                if contenido.get("documento"):
                    doc_path = contenido["documento"]
                    if "/" in doc_path:
                        old_filename = doc_path.split("/")[-1]
                        old_evento_folder = os.path.join(upload_folder, codigo_evento)
                        old_file_path = os.path.join(old_evento_folder, old_filename)
                        
                        if os.path.exists(old_file_path):
                            evento_folder_destino = os.path.join(upload_folder, codigo_destino)
                            os.makedirs(evento_folder_destino, exist_ok=True)
                            
                            extension = os.path.splitext(old_filename)[1] or ".pdf"
                            new_filename = f"documento-{codigo_destino}-{uuid.uuid4().hex[:8]}{extension}"
                            new_file_path = os.path.join(evento_folder_destino, new_filename)
                            
                            import shutil
                            shutil.copy2(old_file_path, new_file_path)
                            
                            nuevo_contenido["documento"] = f"{codigo_destino}/{new_filename}"
            
            elif contenido.get("tipo") == "caso_chatgpt":
                nuevo_contenido["contenido_json"] = contenido.get("contenido_json", "")
            
            elif contenido.get("tipo") == "examen":
                nuevo_contenido["qbank_config"] = contenido.get("qbank_config", "")

            elif contenido.get("tipo") == "tarea":
                nuevo_contenido["requiere_entrega"] = bool(contenido.get("requiere_entrega", False))
                nuevo_contenido["permite_archivo"] = bool(contenido.get("permite_archivo", False))
                nuevo_contenido["instrucciones"] = contenido.get("instrucciones", "")
            
            collection_eva.insert_one(nuevo_contenido)
        
        flash(f"Se copiaron {len(contenidos)} contenidos LMS al evento {codigo_destino}", "success")
        return redirect(url_for("plataforma.listar_contenidos", codigo_evento=codigo_destino))
    
    return render_template("copiar_lms.html", evento=evento_origen)


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

    if secuencial_activo(evento) and cedula and not puede_calificar_evento(evento):
        contenidos_evento = list(
            collection_eva.find({"codigo_evento": codigo_evento}).sort("orden", 1)
        )
        _, pendiente = estado_secuencial(codigo_evento, cedula, contenidos_evento)
        if pendiente:
            return redirect(
                url_for(
                    "plataforma.ver_contenido",
                    codigo_evento=codigo_evento,
                    orden=pendiente["orden"],
                    cedula=cedula,
                    token=token,
                )
            )

    primer_contenido = collection_eva.find_one(
        {"codigo_evento": codigo_evento, "tipo": {"$nin": ["modulo", "submodulo"]}},
        sort=[("orden", 1)],
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
        # Sin contenidos navegables (vacío o solo módulos): mostrar listado
        # para no redirigir a un módulo no navegable.
        contenidos = list(
            collection_eva.find({"codigo_evento": codigo_evento}).sort("orden", 1)
        )
        arbol = build_arbol_lms(contenidos)
        return render_template(
            "plataforma.html",
            evento=evento,
            contenidos=contenidos,
            contenido_actual=None,
            contenido_anterior=None,
            contenido_siguiente=None,
            cedula=cedula,
            token=token,
            arbol=arbol,
            modulo_padre=None,
            submodulo_padre=None,
            secuencial=False,
            contenidos_completados={},
            primer_pendiente_orden=None,
            siguiente_bloqueado=False,
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

    # Los módulos/submódulos son separadores visuales no navegables: redirigir al
    # siguiente contenido navegable (o al anterior si es el último),
    # preservando cedula/token para el acceso por documento.
    if contenido_actual.get("tipo") in TIPOS_NO_NAVEGABLES:
        siguiente_navegable = next(
            (
                c
                for c in contenidos
                if c["orden"] > orden and c.get("tipo") not in TIPOS_NO_NAVEGABLES
            ),
            None,
        )
        anterior_navegable = next(
            (
                c
                for c in reversed(contenidos)
                if c["orden"] < orden and c.get("tipo") not in TIPOS_NO_NAVEGABLES
            ),
            None,
        )
        destino = siguiente_navegable or anterior_navegable
        if destino:
            return redirect(
                url_for(
                    "plataforma.ver_contenido",
                    codigo_evento=codigo_evento,
                    orden=destino["orden"],
                    cedula=cedula,
                    token=token,
                )
            )
        return redirect(
            url_for(
                "plataforma.ver_plataforma",
                codigo_evento=codigo_evento,
                cedula=cedula,
                token=token,
            )
        )

    # --- Avance secuencial (opt-in por evento) ---
    # El bloqueo se evalúa aquí, antes de renderizar: el HTML puede ocultar
    # enlaces, pero la regla vive en el servidor.
    secuencial = (
        secuencial_activo(evento)
        and bool(cedula)
        and not puede_calificar_evento(evento)
    )

    def _nav_secuencial():
        if not secuencial:
            return {
                "secuencial": False,
                "contenidos_completados": {},
                "primer_pendiente_orden": None,
            }
        completados, pendiente = estado_secuencial(codigo_evento, cedula, contenidos)
        return {
            "secuencial": True,
            "contenidos_completados": completados,
            "primer_pendiente_orden": pendiente.get("orden") if pendiente else None,
        }

    nav = _nav_secuencial()
    if secuencial:
        actual_completado = nav["contenidos_completados"].get(
            clave_contenido(contenido_actual), False
        )
        if (
            not actual_completado
            and nav["primer_pendiente_orden"] is not None
            and contenido_actual["orden"] > nav["primer_pendiente_orden"]
        ):
            flash("Completa los contenidos anteriores para continuar.", "error")
            return redirect(
                url_for(
                    "plataforma.ver_contenido",
                    codigo_evento=codigo_evento,
                    orden=nav["primer_pendiente_orden"],
                    cedula=cedula,
                    token=token,
                )
            )
        if not actual_completado and contenido_se_completa_al_abrir(contenido_actual):
            marcar_contenido_visto(codigo_evento, cedula, contenido_actual)
            nav = _nav_secuencial()

    def _siguiente_bloqueado(nav_actual, siguiente):
        if not nav_actual.get("secuencial") or not siguiente:
            return False
        if nav_actual["contenidos_completados"].get(clave_contenido(siguiente)):
            return False
        pendiente = nav_actual.get("primer_pendiente_orden")
        return pendiente is not None and siguiente["orden"] > pendiente

    # Convertir Markdown a HTML solo si el tipo es 'texto'
    if (
        contenido_actual.get("tipo") == "texto"
        and "contenido_texto" in contenido_actual
    ):
        contenido_actual["contenido_texto"] = markdown.markdown(
            contenido_actual["contenido_texto"]
        )

    if contenido_actual.get("tipo") == "video":
        contenido_actual["url_video_embed"] = url_video_embed(
            contenido_actual.get("url_video")
        )

    # Mostrar examen si el tipo es 'examen' y tiene qbank_config
    if contenido_actual.get("tipo") == "examen" and "qbank_config" in contenido_actual:
        codigo_qbank, num_preguntas, aleatorio, formativo, persistencia, evaluable = parse_qbank_config(
            contenido_actual["qbank_config"]
        )
        if codigo_qbank:
            # Persistencia: cargar resultado guardado si existe
            resultado_persistente = None
            respuestas_guardadas = None
            if persistencia and cedula:
                resultado_persistente = collection_exam_results.find_one({
                    "codigo_evento": codigo_evento,
                    "orden_examen": orden,
                    "cedula_participante": cedula,
                })

            if resultado_persistente:
                preguntas_ids = resultado_persistente.get("respuestas", [])
                pregunta_ids_list = [r["pregunta_id"] for r in preguntas_ids]
                preguntas = [
                    collection_qbanks_data.find_one({"_id": ObjectId(pid)})
                    for pid in pregunta_ids_list
                    if pid
                ]
                son_todas_encuesta = all(
                    p.get("tipo") == "encuesta" for p in preguntas if p
                )
                if son_todas_encuesta:
                    puntaje = (0, 0)
                else:
                    puntaje = (
                        resultado_persistente["respuestas_correctas"],
                        resultado_persistente["total_preguntas"],
                    )
                respuestas_guardadas = {}
                for i, r in enumerate(preguntas_ids):
                    respuestas_guardadas[str(i)] = r.get("respuesta", [])
            elif request.method == "POST":
                preguntas_ids = request.form.get("preguntas_ids", "").split(",")
                preguntas = [
                    collection_qbanks_data.find_one({"_id": ObjectId(pid)})
                    for pid in preguntas_ids
                    if pid
                ]
                puntaje = None
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
            if request.method == "POST" and not resultado_persistente:
                correctas = 0
                total_evaluables = 0
                respuestas_usuario = []
                for i, pregunta in enumerate(preguntas):
                    respuesta_usuario = request.form.getlist(f"resp_{i}")
                    if pregunta.get("tipo") == "encuesta":
                        respuestas_usuario.append(
                            {
                                "pregunta_id": str(pregunta["_id"]),
                                "respuesta": respuesta_usuario,
                            }
                        )
                    else:
                        es_correcta = set(map(str, pregunta["respuestas_correctas"])) == set(respuesta_usuario)
                        respuestas_usuario.append(
                            {
                                "pregunta_id": str(pregunta["_id"]),
                                "respuesta": respuesta_usuario,
                                "correcta": es_correcta,
                            }
                        )
                        if es_correcta:
                            correctas += 1
                        total_evaluables += 1
                puntaje = (correctas, total_evaluables)

                respuestas_guardadas = {}
                for i, r in enumerate(respuestas_usuario):
                    respuestas_guardadas[str(i)] = r.get("respuesta", [])

                # Calcular calificación como porcentaje (solo preguntas evaluables)
                total_para_puntaje = total_evaluables if total_evaluables > 0 else len(preguntas)
                calificacion = (
                    (correctas / total_para_puntaje) * 100 if total_para_puntaje > 0 else 0
                )

                # Obtener cédula del participante desde los parámetros
                cedula_participante = request.args.get("cedula")

                # Verificar que el evento es virtual antes de guardar
                # Solo guardar si NO es formativo o si es formativo pero queremos registro
                if (
                    evento.get("lms_activo", evento.get("modalidad") in ["Virtual asincrónica", "Virtual sincrónica", "Híbrida"])
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
                        # FK estable ante reordenamientos (ver mejor_resultado_examen)
                        "examen_id": _id_str(contenido_actual),
                        "cedula_participante": cedula_participante,
                        "numero_intento": numero_intento,
                        "calificacion": calificacion,
                        "respuestas": respuestas_usuario,
                        "fecha_envio": datetime.now(),
                        "titulo_examen": contenido_actual.get("titulo", "Sin título"),
                        "titulo_evento": evento.get("titulo", "Sin título"),
                        "total_preguntas": total_evaluables if total_evaluables > 0 else len(preguntas),
                        "respuestas_correctas": correctas if total_evaluables > 0 else len(preguntas),
                        "formativo": formativo,  # Marcar si es formativo o no
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

            # Historial de intentos para exámenes sumativos
            # (incluye FK estable examen_id + fallback a orden para históricos)
            intentos_historial = []
            if cedula and not formativo:
                intentos_historial = list(
                    collection_exam_results.find(
                        {
                            "codigo_evento": codigo_evento,
                            "cedula_participante": cedula,
                            "formativo": formativo,
                            "$or": [
                                {"examen_id": _id_str(contenido_actual)},
                                {"examen_id": None, "orden_examen": orden},
                                {"examen_id": {"$exists": False}, "orden_examen": orden},
                            ],
                        },
                        {
                            "numero_intento": 1,
                            "calificacion": 1,
                            "total_preguntas": 1,
                            "respuestas_correctas": 1,
                            "fecha_envio": 1,
                            "_id": 0,
                        },
                    ).sort("numero_intento", 1)
                )

            # Redirigir a encuesta si el examen sumativo fue aprobado y el evento requiere encuesta
            if request.method == "POST" and not formativo and puntaje and puntaje[1] > 0 and puntaje[0] / puntaje[1] >= 0.8:
                from app.verifica_encuesta import requires_survey_completion, has_completed_survey_v2
                if requires_survey_completion(evento) and not has_completed_survey_v2(cedula, codigo_evento):
                    flash('¡Examen aprobado! Completa la encuesta de evaluación para descargar tu certificado.', 'success')
                    return redirect(url_for('encuesta_satisfaccion', codigo_evento=codigo_evento, cedula=cedula, from_examen=1))

            # Calcular progreso de sumativas+tareas y estado del certificado.
            # Las tareas manuales cuentan igual que los exámenes sumativos.
            total_sumativos = 0
            aprobados_sumativos = 0
            total_tareas = 0
            aprobadas_tareas = 0
            todos_aprobados = False
            encuesta_completada = False
            certificado_disponible = False

            if not formativo and cedula and nanoid and evento.get('lms_activo'):
                from app.verifica_encuesta import requires_survey_completion, has_completed_survey_v2

                # Obtener todos los exámenes sumativos del evento
                examenes_evento = list(collection_eva.find({
                    'codigo_evento': codigo_evento,
                    'tipo': 'examen'
                }))
                for ex in examenes_evento:
                    qbank_config = ex.get('qbank_config', '')
                    if qbank_config:
                        _, _, _, ex_formativo, _, _ = parse_qbank_config(qbank_config)
                        if not ex_formativo:
                            total_sumativos += 1

                # Verificar cuáles sumativos están aprobados (>=80%).
                # FK estable: se matchea por examen_id con fallback a orden
                # para históricos previos al blindaje/remap.
                if total_sumativos > 0:
                    examenes_sumativos = []
                    for ex in examenes_evento:
                        qbank_config = ex.get('qbank_config', '')
                        if qbank_config:
                            _, _, _, ex_formativo, _, _ = parse_qbank_config(qbank_config)
                            if not ex_formativo:
                                examenes_sumativos.append(ex)

                    ids_sumativos = [_id_str(ex) for ex in examenes_sumativos]
                    ordenes_sumativos = [ex.get('orden') for ex in examenes_sumativos]
                    resultados_sumativos = list(collection_exam_results.find({
                        'codigo_evento': codigo_evento,
                        'cedula_participante': cedula,
                        '$or': [
                            {'examen_id': {'$in': ids_sumativos}},
                            {'examen_id': None, 'orden_examen': {'$in': ordenes_sumativos}},
                            {'examen_id': {'$exists': False}, 'orden_examen': {'$in': ordenes_sumativos}},
                        ],
                    }))
                    for ex in examenes_sumativos:
                        mejor = mejor_resultado_examen(resultados_sumativos, ex)
                        if mejor and mejor.get('calificacion', 0) >= UMBRAL_APROBACION:
                            aprobados_sumativos += 1

                # Tareas manuales: cuentan igual que las sumativas (>=80).
                tareas_evento, entregas_tareas = estado_tareas_evento(
                    codigo_evento, cedula
                )
                total_tareas = len(tareas_evento)
                for t in tareas_evento:
                    ent = entregas_tareas.get(_id_str(t))
                    if (
                        ent
                        and ent.get("calificacion") is not None
                        and ent.get("calificacion", 0) >= UMBRAL_APROBACION
                    ):
                        aprobadas_tareas += 1

                todos_aprobados = (
                    (total_sumativos + total_tareas) > 0
                    and aprobados_sumativos == total_sumativos
                    and aprobadas_tareas == total_tareas
                )

                # Verificar encuesta
                requiere_encuesta = requires_survey_completion(evento)
                if requiere_encuesta:
                    encuesta_completada = has_completed_survey_v2(cedula, codigo_evento)
                else:
                    encuesta_completada = True

                # Certificado disponible: todos los sumativos aprobados + encuesta completada (si aplica)
                certificado_disponible = todos_aprobados and encuesta_completada

            # Breadcrumb jerárquico (no afecta calificación)
            contenidos_by_id_ex = {_id_str(c): c for c in contenidos}
            modulo_padre_ex, submodulo_padre_ex = breadcrumb_lms(
                contenidos_by_id_ex, contenido_actual
            )
            arbol_ex = build_arbol_lms(contenidos)
            if secuencial and request.method == "POST":
                # El intento se guardó arriba: recalcular desbloqueo.
                nav = _nav_secuencial()
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
                formativo=formativo,  # Pasar al template
                intentos_historial=intentos_historial,
                respuestas_guardadas=respuestas_guardadas,
                total_sumativos=total_sumativos,
                aprobados_sumativos=aprobados_sumativos,
                total_tareas=total_tareas,
                aprobadas_tareas=aprobadas_tareas,
                todos_aprobados=todos_aprobados,
                encuesta_completada=encuesta_completada,
                certificado_disponible=certificado_disponible,
                arbol=arbol_ex,
                modulo_padre=modulo_padre_ex,
                submodulo_padre=submodulo_padre_ex,
                **nav,
            )



    # Mostrar tarea de calificación manual si el tipo es 'tarea'
    if contenido_actual.get("tipo") == "tarea":
        tarea_id = _id_str(contenido_actual)
        requiere_entrega = bool(contenido_actual.get("requiere_entrega", False))
        permite_archivo = bool(contenido_actual.get("permite_archivo", False))
        instrucciones_html = None
        if contenido_actual.get("instrucciones"):
            instrucciones_html = markdown.markdown(
                contenido_actual["instrucciones"]
            )

        entrega = None
        if cedula:
            entrega = collection_tarea_entregas.find_one(
                {
                    "codigo_evento": codigo_evento,
                    "cedula_participante": cedula,
                    "$or": [
                        {"tarea_id": tarea_id},
                        {"tarea_id": None, "orden_tarea": orden},
                        {
                            "tarea_id": {"$exists": False},
                            "orden_tarea": orden,
                        },
                    ],
                }
            )

        if request.method == "POST":
            if not cedula:
                abort(401)
            if not requiere_entrega:
                abort(403)
            texto_entrega = (request.form.get("texto_entrega") or "").strip()
            archivo_path = entrega.get("archivo_path") if entrega else None
            archivo_file = (
                request.files.get("archivo") if permite_archivo else None
            )
            if archivo_file and archivo_file.filename:
                if not archivo_file.filename.lower().endswith(".pdf"):
                    flash("Solo se permiten archivos PDF.", "error")
                    return redirect(request.url)
                evento_folder = os.path.join(
                    current_app.config["UPLOAD_FOLDER"], codigo_evento
                )
                os.makedirs(evento_folder, exist_ok=True)
                safe_ced = re.sub(r"[^A-Za-z0-9_-]", "_", cedula)
                archivo_filename = (
                    f"tarea-{codigo_evento}-{orden:02d}-{safe_ced}.pdf"
                )
                archivo_file.save(
                    os.path.join(evento_folder, archivo_filename)
                )
                archivo_path = f"{codigo_evento}/{archivo_filename}"
            if not texto_entrega and not archivo_path:
                flash(
                    "Debes escribir tu entrega o adjuntar el archivo PDF.",
                    "error",
                )
                return redirect(request.url)
            ahora = datetime.now()
            if entrega:
                collection_tarea_entregas.update_one(
                    {"_id": entrega["_id"]},
                    {
                        "$set": {
                            "tarea_id": tarea_id,
                            "orden_tarea": orden,
                            "texto_entrega": texto_entrega,
                            "archivo_path": archivo_path,
                            "fecha_entrega": ahora,
                            "titulo_tarea": contenido_actual.get(
                                "titulo", "Sin título"
                            ),
                            "titulo_evento": evento.get(
                                "titulo", "Sin título"
                            ),
                        }
                    },
                )
            else:
                collection_tarea_entregas.insert_one(
                    {
                        "codigo_evento": codigo_evento,
                        "tarea_id": tarea_id,
                        "orden_tarea": orden,
                        "cedula_participante": cedula,
                        "texto_entrega": texto_entrega,
                        "archivo_path": archivo_path,
                        "calificacion": None,
                        "feedback": "",
                        "estado": "pendiente",
                        "fecha_entrega": ahora,
                        "titulo_tarea": contenido_actual.get(
                            "titulo", "Sin título"
                        ),
                        "titulo_evento": evento.get("titulo", "Sin título"),
                    }
                )
            flash("Entrega guardada correctamente.", "success")
            return redirect(request.url)

        participante = (
            collection_participantes.find_one(
                {
                    "cedula": cedula,
                    "codigo_evento": codigo_evento,
                    "rol": "participante",
                }
            )
            if cedula
            else None
        )
        nanoid = participante.get("nanoid") if participante else None
        prog = (
            progreso_lms(codigo_evento, cedula, evento)
            if (cedula and nanoid and evento.get("lms_activo"))
            else None
        )
        contenidos_by_id_t = {_id_str(c): c for c in contenidos}
        modulo_padre_t, submodulo_padre_t = breadcrumb_lms(
            contenidos_by_id_t, contenido_actual
        )
        arbol_t = build_arbol_lms(contenidos)
        navegables_t = [
            c for c in contenidos if c.get("tipo") not in TIPOS_NO_NAVEGABLES
        ]
        idx_t = navegables_t.index(contenido_actual)
        anterior_t = navegables_t[idx_t - 1] if idx_t > 0 else None
        siguiente_t = (
            navegables_t[idx_t + 1] if idx_t < len(navegables_t) - 1 else None
        )
        if secuencial and request.method == "POST":
            # La entrega ya se guardó arriba: recalcular desbloqueo.
            nav = _nav_secuencial()
        nav_t = dict(nav)
        nav_t["siguiente_bloqueado"] = _siguiente_bloqueado(nav_t, siguiente_t)
        return render_template(
            "plataforma.html",
            evento=evento,
            contenidos=contenidos,
            contenido_actual=contenido_actual,
            contenido_anterior=anterior_t,
            contenido_siguiente=siguiente_t,
            cedula=cedula,
            token=token,
            arbol=arbol_t,
            modulo_padre=modulo_padre_t,
            submodulo_padre=submodulo_padre_t,
            instrucciones_html=instrucciones_html,
            entrega=entrega,
            requiere_entrega=requiere_entrega,
            permite_archivo=permite_archivo,
            nanoid=nanoid,
            prog=prog,
            **nav_t,
        )

    # Encontrar el contenido anterior y el siguiente (saltando módulos y
    # submódulos, que son separadores no navegables)
    navegables = [c for c in contenidos if c.get("tipo") not in TIPOS_NO_NAVEGABLES]
    indice_actual = navegables.index(contenido_actual)
    contenido_anterior = navegables[indice_actual - 1] if indice_actual > 0 else None
    contenido_siguiente = (
        navegables[indice_actual + 1] if indice_actual < len(navegables) - 1 else None
    )
    contenidos_by_id = {_id_str(c): c for c in contenidos}
    modulo_padre, submodulo_padre = breadcrumb_lms(contenidos_by_id, contenido_actual)
    arbol = build_arbol_lms(contenidos)
    nav["siguiente_bloqueado"] = _siguiente_bloqueado(nav, contenido_siguiente)

    return render_template(
        "plataforma.html",
        evento=evento,
        contenidos=contenidos,
        contenido_actual=contenido_actual,
        contenido_anterior=contenido_anterior,
        contenido_siguiente=contenido_siguiente,
        cedula=cedula,
        token=token,
        arbol=arbol,
        modulo_padre=modulo_padre,
        submodulo_padre=submodulo_padre,
        **nav,
    )


@plataforma_bp.route(
    "/plataforma/<codigo_evento>/<int:orden>/progreso", methods=["POST"]
)
@token_required
def registrar_progreso(codigo_evento, orden):
    """Acumula el tiempo reproducido de un video y evalúa el umbral del 50%."""
    cedula = request.args.get("cedula")
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)
    contenido = collection_eva.find_one(
        {"codigo_evento": codigo_evento, "orden": orden}
    )
    if not contenido:
        abort(404)
    if contenido.get("tipo") != "video":
        return jsonify({"error": "El contenido no es un video."}), 400
    if not secuencial_activo(evento) or puede_calificar_evento(evento):
        return jsonify({"completado": True, "porcentaje": 100})

    datos = request.get_json(silent=True) or request.form
    try:
        delta = float(datos.get("delta") or 0)
        duracion = float(datos.get("duracion") or 0)
    except (TypeError, ValueError):
        return jsonify({"error": "Datos de progreso inválidos."}), 400
    if not cedula or delta <= 0 or duracion <= 0:
        return jsonify({"error": "Datos de progreso inválidos."}), 400

    delta = min(delta, MAX_DELTA_SEGUNDOS)
    porcentaje, completado = registrar_progreso_video(
        codigo_evento, cedula, contenido, delta, duracion
    )
    return jsonify({"porcentaje": porcentaje, "completado": completado})


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
        
        # Función para generar nombre único de archivo
        def generar_nombre_archivo(original_filename):
            extension = os.path.splitext(original_filename)[1]
            unique_id = uuid.uuid4().hex[:8]
            return f"archivo-{codigo_qbank}-{unique_id}{extension}"

        # Procesar opciones
        opciones = []
        for i in range(int(request.form["num_opciones"])):
            texto = request.form.get(f"opcion_texto_{i}", "")
            imagen = None

            # Verificar si se subió una nueva imagen
            if f"opcion_imagen_{i}" in request.files:
                file = request.files[f"opcion_imagen_{i}"]
                if file and file.filename:
                    filename = generar_nombre_archivo(file.filename)
                    file_path = os.path.join(evento_folder, filename)
                    file.save(file_path)
                    imagen = f"{codigo_qbank}/{filename}"

            # Si no se subió nueva imagen, intentar mantener la existente
            if not imagen:
                imagen = request.form.get(f"opcion_imagen_actual_{i}")

            opciones.append({"texto": texto, "imagen": imagen})

        # Guardar imágenes de la pregunta (añadir nuevas sin eliminar existentes)
        nuevas_imagenes = [f for f in imagenes_pregunta if f and f.filename]
        imagenes = list(pregunta.get("imagenes", []))  # Mantener existentes
        for file in nuevas_imagenes:
            filename = generar_nombre_archivo(file.filename)
            file_path = os.path.join(evento_folder, filename)
            file.save(file_path)
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
### Eliminar una imagen de una pregunta
###
@plataforma_bp.route(
    "/tablero/qbanks/<codigo_qbank>/editar_pregunta/<pregunta_id>/eliminar_imagen",
    methods=["POST"],
)
@login_required
@lms_edit_required
def eliminar_imagen_pregunta(codigo_qbank, pregunta_id):
    pregunta = collection_qbanks_data.find_one(
        {"_id": ObjectId(pregunta_id), "codigo_qbank": codigo_qbank}
    )
    if not pregunta:
        flash("Pregunta no encontrada.", "error")
        return redirect(url_for("plataforma.ver_qbank", codigo_qbank=codigo_qbank))

    imagen_path = request.form.get("imagen_path")
    if not imagen_path:
        flash("No se especificó imagen.", "error")
        return redirect(
            url_for(
                "plataforma.editar_pregunta_qbank",
                codigo_qbank=codigo_qbank,
                pregunta_id=pregunta_id,
            )
        )

    ruta_absoluta = os.path.join(
        current_app.config["UPLOAD_FOLDER"], imagen_path
    )
    if os.path.isfile(ruta_absoluta):
        os.remove(ruta_absoluta)

    collection_qbanks_data.update_one(
        {"_id": ObjectId(pregunta_id)},
        {"$pull": {"imagenes": imagen_path}},
    )

    flash("Imagen eliminada.", "success")
    return redirect(
        url_for(
            "plataforma.editar_pregunta_qbank",
            codigo_qbank=codigo_qbank,
            pregunta_id=pregunta_id,
        )
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

        # Eliminar archivos del filesystem (imágenes de la pregunta y opciones)
        upload_folder = current_app.config["UPLOAD_FOLDER"]
        archivos_a_eliminar = list(pregunta.get("imagenes", []))
        for opcion in pregunta.get("opciones", []):
            if opcion.get("imagen"):
                archivos_a_eliminar.append(opcion["imagen"])
        for ruta_relativa in archivos_a_eliminar:
            if ruta_relativa:
                ruta_absoluta = os.path.join(upload_folder, ruta_relativa)
                if os.path.isfile(ruta_absoluta):
                    os.remove(ruta_absoluta)

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
        
        # Función para generar nombre único de archivo
        def generar_nombre_archivo(original_filename):
            extension = os.path.splitext(original_filename)[1]
            unique_id = uuid.uuid4().hex[:8]
            return f"archivo-{codigo_qbank}-{unique_id}{extension}"
        
        # Procesar opciones y sus imágenes
        for i in range(int(request.form["num_opciones"])):
            texto = request.form.get(f"opcion_texto_{i}", "")
            imagen = None
            if f"opcion_imagen_{i}" in request.files:
                file = request.files[f"opcion_imagen_{i}"]
                if file and file.filename:
                    filename = generar_nombre_archivo(file.filename)
                    file_path = os.path.join(evento_folder, filename)
                    file.save(file_path)
                    imagen = f"{codigo_qbank}/{filename}"
            opciones.append({"texto": texto, "imagen": imagen})

        # Guardar imágenes de la pregunta
        imagenes = []
        for file in imagenes_pregunta:
            if file and file.filename:
                filename = generar_nombre_archivo(file.filename)
                file_path = os.path.join(evento_folder, filename)
                file.save(file_path)
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
    # Ejemplo: [O5W4YTK2 preguntas=3 aleatorio=no formativo=si persistencia=no evaluable=si]
    params = {}
    match = re.match(r"\[(\w+)", config_str)
    if not match:
        return None, None, None, False, False, True
    params["codigo"] = match.group(1)
    for kv in re.finditer(r"(\w+)=(si|no|\d+)", config_str):
        key, val = kv.group(1), kv.group(2)
        params[key] = val
    codigo = params.get("codigo")
    num_preguntas = int(params.get("preguntas", 0))
    aleatorio = params.get("aleatorio", "no") == "si"
    formativo = params.get("formativo", "no") == "si"
    persistencia = params.get("persistencia", "no") == "si"
    evaluable = params.get("evaluable", "si") == "si"
    if not codigo or num_preguntas == 0:
        return None, None, None, False, False, True
    return codigo, num_preguntas, aleatorio, formativo, persistencia, evaluable


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

        # Verificar que el evento existe y tiene modalidad virtual o híbrida
        evento = collection_eventos.find_one(
            {"codigo": codigo_evento, "$or": [{"lms_activo": True}, {"modalidad": {"$in": ["Virtual asincrónica", "Virtual sincrónica", "Híbrida"]}}]}
        )

        if not evento:
            return jsonify(
                {"error": "Evento no encontrado o modalidad no compatible"}
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
            # FK estable ante reordenamientos (ver mejor_resultado_examen)
            "examen_id": _id_str(examen) if examen else None,
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
