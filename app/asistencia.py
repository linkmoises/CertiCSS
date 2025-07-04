from flask import Blueprint, render_template, request, flash, redirect, url_for, session, send_file
from app import db, collection_eventos, collection_participantes
from pymongo import MongoClient
from config import config
from datetime import datetime
from flask_login import login_required, current_user
import csv
import io

asistencia_bp = Blueprint('asistencia', __name__)


###
### Crear colección para seguimiento
###
collection_seguimiento = db['seguimiento_asistencia']


###
### Asistencia dinámica
###
@asistencia_bp.route("/tablero/asistencia-dinamica", methods=['GET', 'POST'])
@login_required
def asistencia_dinamica():
    # Inicializar las listas en la sesión si no existen
    if 'cedulas_historial' not in session:
        session['cedulas_historial'] = []
    if 'eventos_historial' not in session:
        session['eventos_historial'] = []
    if 'nombres_historial' not in session:
        session['nombres_historial'] = {}
    
    # Intentar recuperar el historial de la base de datos
    seguimiento = collection_seguimiento.find_one({'_id': f'seguimiento_{current_user.id}'})
    if seguimiento:
        session['cedulas_historial'] = seguimiento.get('cedulas', [])
        session['eventos_historial'] = seguimiento.get('eventos', [])
        session['nombres_historial'] = seguimiento.get('nombres', {})
    
    if request.method == 'POST':
        # Obtener las cédulas y códigos de evento del formulario
        cedulas_texto = request.form.get('cedulas', '').strip()
        eventos_texto = request.form.get('eventos', '').strip()
        
        # Convertir el texto en listas, eliminando líneas vacías
        cedulas_nuevas = [c.strip() for c in cedulas_texto.split('\n') if c.strip()]
        codigos_evento_nuevos = [e.strip() for e in eventos_texto.split('\n') if e.strip()]
        
        # Combinar con el historial existente
        session['cedulas_historial'] = list(set(session['cedulas_historial'] + cedulas_nuevas))
        session['eventos_historial'] = list(set(session['eventos_historial'] + codigos_evento_nuevos))
        
        # Guardar en la base de datos
        collection_seguimiento.update_one(
            {'_id': f'seguimiento_{current_user.id}'},
            {
                '$set': {
                    'cedulas': session['cedulas_historial'],
                    'eventos': session['eventos_historial'],
                    'nombres': session['nombres_historial'],
                    'ultima_actualizacion': datetime.now(),
                    'usuario_id': current_user.id
                }
            },
            upsert=True
        )
        
        # Validar que se hayan ingresado cédulas y eventos
        if not cedulas_nuevas and not codigos_evento_nuevos:
            flash('Por favor ingrese al menos una cédula o un código de evento', 'warning')
            return redirect(url_for('asistencia.asistencia_dinamica'))
    
    # Consulta 1: Obtener los nombres de eventos por los códigos seleccionados
    eventos = list(collection_eventos.find(
        {"codigo": {"$in": session['eventos_historial']}},
        {"_id": 0, "codigo": 1, "nombre": 1, "fecha_inicio": 1}
    ).sort("fecha_inicio", 1))

    # Validar que todos los códigos de evento existan
    codigos_encontrados = {evento["codigo"] for evento in eventos}
    codigos_no_encontrados = set(session['eventos_historial']) - codigos_encontrados
    if codigos_no_encontrados:
        flash(f'Los siguientes códigos de evento no existen: {", ".join(codigos_no_encontrados)}', 'warning')
        # Remover los códigos no encontrados del historial
        session['eventos_historial'] = list(codigos_encontrados)
        # Actualizar en la base de datos
        collection_seguimiento.update_one(
            {'_id': f'seguimiento_{current_user.id}'},
            {'$set': {'eventos': session['eventos_historial']}},
            upsert=True
        )
        return redirect(url_for('asistencia.asistencia_dinamica'))

    # Construir la tabla de seguimiento
    tabla = []
    for cedula in session['cedulas_historial']:
        fila = {
            "cedula": cedula,
            "nombre": session['nombres_historial'].get(cedula, ''),
            "asistencia": {codigo: False for codigo in session['eventos_historial']}
        }

        # Consulta 2: Buscar registros de asistencia para esta cédula y eventos
        registros = list(collection_participantes.find({
            "cedula": cedula,
            "codigo_evento": {"$in": session['eventos_historial']}
        }))
        
        # Marcar como True los eventos donde el participante tiene registro
        for r in registros:
            fila["asistencia"][r["codigo_evento"]] = True

        tabla.append(fila)

    return render_template("asistencia-dinamica.html", 
                         tabla=tabla, 
                         eventos=eventos,
                         cedulas_historial=session['cedulas_historial'],
                         eventos_historial=session['eventos_historial'],
                         nombres_historial=session['nombres_historial'])


###
### Actualizar nombre
###
@asistencia_bp.route("/tablero/asistencia-dinamica/<cedula>/actualizar-nombre", methods=['POST'])
@login_required
def actualizar_nombre(cedula):
    nombre = request.form.get('nombre', '').strip()
    if cedula in session['cedulas_historial']:
        session['nombres_historial'][cedula] = nombre
        # Actualizar en la base de datos
        collection_seguimiento.update_one(
            {'_id': f'seguimiento_{current_user.id}'},
            {'$set': {'nombres': session['nombres_historial']}},
            upsert=True
        )
        flash(f'Nombre actualizado para la cédula {cedula}', 'success')
    return redirect(url_for('asistencia.asistencia_dinamica'))


###
### Limpiar seguimiento
###
@asistencia_bp.route("/tablero/asistencia-dinamica/limpiar-seguimiento", methods=['POST'])
@login_required
def limpiar_seguimiento():
    # Limpiar la sesión
    session['cedulas_historial'] = []
    session['eventos_historial'] = []
    session['nombres_historial'] = {}
    
    # Limpiar la base de datos
    collection_seguimiento.delete_one({'_id': f'seguimiento_{current_user.id}'})
    
    flash('Seguimiento limpiado exitosamente', 'success')
    return redirect(url_for('asistencia.asistencia_dinamica'))


###
### Eliminar cédula
###
@asistencia_bp.route("/tablero/asistencia-dinamica/<cedula>/eliminar-cedula", methods=['POST'])
@login_required
def eliminar_cedula(cedula):
    if cedula in session['cedulas_historial']:
        session['cedulas_historial'].remove(cedula)
        if cedula in session['nombres_historial']:
            del session['nombres_historial'][cedula]
        # Actualizar en la base de datos
        collection_seguimiento.update_one(
            {'_id': f'seguimiento_{current_user.id}'},
            {
                '$set': {
                    'cedulas': session['cedulas_historial'],
                    'nombres': session['nombres_historial']
                }
            },
            upsert=True
        )
        flash(f'Cédula {cedula} eliminada del seguimiento', 'success')
    return redirect(url_for('asistencia.asistencia_dinamica'))


###
### Eliminar evento del seguimiento
###
@asistencia_bp.route("/tablero/asistencia-dinamica/eliminar-evento/<codigo>", methods=['POST'])
@login_required
def eliminar_evento(codigo):
    if codigo in session['eventos_historial']:
        session['eventos_historial'].remove(codigo)
        # Actualizar en la base de datos
        collection_seguimiento.update_one(
            {'_id': f'seguimiento_{current_user.id}'},
            {'$set': {'eventos': session['eventos_historial']}},
            upsert=True
        )
        flash(f'Evento {codigo} eliminado del seguimiento', 'success')
    return redirect(url_for('asistencia.asistencia_dinamica'))


###
### Descargar seguimiento
###
@asistencia_bp.route("/tablero/asistencia-dinamica/descargar-seguimiento", methods=['GET'])
@login_required
def descargar_seguimiento():
    # Obtener los datos del seguimiento
    seguimiento = collection_seguimiento.find_one({'_id': f'seguimiento_{current_user.id}'})
    if not seguimiento:
        flash('No hay datos de seguimiento para descargar', 'warning')
        return redirect(url_for('asistencia.asistencia_dinamica'))

    # Obtener los eventos
    eventos = list(collection_eventos.find(
        {"codigo": {"$in": seguimiento.get('eventos', [])}},
        {"_id": 0, "codigo": 1, "nombre": 1}
    ))

    # Crear un buffer en memoria para el CSV
    output = io.StringIO()
    writer = csv.writer(output)

    # Escribir el encabezado
    header = ['Cédula', 'Nombre'] + [f"{evento['codigo']} ({evento['nombre']})" for evento in eventos]
    writer.writerow(header)

    # Escribir los datos
    for cedula in seguimiento.get('cedulas', []):
        # Buscar registros de asistencia para esta cédula
        registros = list(collection_participantes.find({
            "cedula": cedula,
            "codigo_evento": {"$in": seguimiento.get('eventos', [])}
        }))
        
        # Crear una fila con la asistencia
        fila = [cedula, seguimiento.get('nombres', {}).get(cedula, '')]
        for evento in eventos:
            asistio = any(r["codigo_evento"] == evento["codigo"] for r in registros)
            fila.append("1" if asistio else "0")
        
        writer.writerow(fila)

    # Preparar el archivo para descarga
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'seguimiento_asistencia_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    ) 