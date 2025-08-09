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
        
        # Procesar cada línea de cédulas
        cedulas_nuevas = []
        for line in cedulas_texto.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            # Verificar si la línea tiene el formato "cedula, nombre"
            if ',' in line:
                parts = [p.strip() for p in line.split(',', 1)]  # Dividir solo en la primera coma
                if len(parts) == 2 and parts[0] and parts[1]:
                    cedula = parts[0]
                    nombre = parts[1]
                    # Agregar al historial de nombres
                    session['nombres_historial'][cedula] = nombre
                    cedulas_nuevas.append(cedula)
                    continue
            
            # Si no tiene formato de nombre, agregar como está
            cedulas_nuevas.append(line)
        
        # Procesar códigos de evento
        codigos_evento_nuevos = [e.strip() for e in eventos_texto.split('\n') if e.strip()]
        
        # Combinar con el historial existente (usar set para evitar duplicados)
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
    
    # Formatear fechas
    for evento in eventos:
        if 'fecha_inicio' in evento and evento['fecha_inicio']:
            if isinstance(evento['fecha_inicio'], str):
                try:
                    fecha = datetime.strptime(evento['fecha_inicio'], '%Y-%m-%d')
                    evento['fecha_formateada'] = fecha.strftime('%d/%m/%y')
                except (ValueError, TypeError):
                    evento['fecha_formateada'] = evento['fecha_inicio']
            elif hasattr(evento['fecha_inicio'], 'strftime'):
                evento['fecha_formateada'] = evento['fecha_inicio'].strftime('%d/%m/%y')
            else:
                evento['fecha_formateada'] = str(evento['fecha_inicio'])
        else:
            evento['fecha_formateada'] = ''

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

    # Obtener listas guardadas del usuario actual
    collection_listas = db['listas_seguimiento']
    listas_guardadas = list(collection_listas.find(
        {'usuario_id': current_user.id},
        sort=[('fecha_creacion', -1)]  # Ordenar por fecha de creación descendente
    ))

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
                         nombres_historial=session['nombres_historial'],
                         listas_guardadas=listas_guardadas)


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
### Guardar lista de seguimiento
###
@asistencia_bp.route("/tablero/asistencia-dinamica/guardar-lista", methods=['POST'])
@login_required
def guardar_lista():
    if 'cedulas_historial' not in session or not session['cedulas_historial']:
        flash('No hay datos para guardar', 'warning')
        return redirect(url_for('asistencia.asistencia_dinamica'))
    
    nombre_lista = request.form.get('nombre_lista', '').strip()
    if not nombre_lista:
        flash('Debe ingresar un nombre para la lista', 'warning')
        return redirect(url_for('asistencia.asistencia_dinamica'))
    
    # Guardar la lista en la base de datos
    lista_data = {
        'nombre': nombre_lista,
        'cedulas': session['cedulas_historial'],
        'eventos': session.get('eventos_historial', []),
        'nombres': session.get('nombres_historial', {}),
        'fecha_creacion': datetime.now(),
        'usuario_id': current_user.id
    }
    
    # Usar el nombre como _id para evitar duplicados por usuario
    lista_id = f"lista_{current_user.id}_{nombre_lista.lower().replace(' ', '_')}"
    
    collection_listas = db['listas_seguimiento']
    collection_listas.update_one(
        {'_id': lista_id},
        {'$set': lista_data},
        upsert=True
    )
    
    flash(f'Lista "{nombre_lista}" guardada correctamente', 'success')
    return redirect(url_for('asistencia.asistencia_dinamica'))

###
### Cargar lista de seguimiento
###
@asistencia_bp.route("/tablero/asistencia-dinamica/cargar-lista/<lista_id>")
@login_required
def cargar_lista(lista_id):
    collection_listas = db['listas_seguimiento']
    lista = collection_listas.find_one({'_id': lista_id, 'usuario_id': current_user.id})
    
    if not lista:
        flash('Lista no encontrada', 'error')
        return redirect(url_for('asistencia.asistencia_dinamica'))
    
    # Actualizar la sesión con los datos de la lista
    session['cedulas_historial'] = lista.get('cedulas', [])
    session['eventos_historial'] = lista.get('eventos', [])
    session['nombres_historial'] = lista.get('nombres', {})
    
    # Actualizar en la colección de seguimiento
    collection_seguimiento.update_one(
        {'_id': f'seguimiento_{current_user.id}'},
        {'$set': {
            'cedulas': lista.get('cedulas', []),
            'eventos': lista.get('eventos', []),
            'nombres': lista.get('nombres', {})
        }},
        upsert=True
    )
    
    flash(f'Lista "{lista.get("nombre")}" cargada correctamente', 'success')
    return redirect(url_for('asistencia.asistencia_dinamica'))

###
### Eliminar lista de seguimiento
###
@asistencia_bp.route("/tablero/asistencia-dinamica/eliminar-lista/<lista_id>")
@login_required
def eliminar_lista(lista_id):
    collection_listas = db['listas_seguimiento']
    result = collection_listas.delete_one({'_id': lista_id, 'usuario_id': current_user.id})
    
    if result.deleted_count > 0:
        flash('Lista eliminada correctamente', 'success')
    else:
        flash('No se pudo eliminar la lista', 'error')
    
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

    # Obtener los eventos con su fecha de inicio
    eventos = list(collection_eventos.find(
        {"codigo": {"$in": seguimiento.get('eventos', [])}},
        {"_id": 0, "codigo": 1, "nombre": 1, "fecha_inicio": 1}
    ))

    # Crear un buffer en memoria para el CSV
    output = io.StringIO()
    writer = csv.writer(output)

    # Escribir el encabezado con la fecha de inicio formateada
    header = ['Cédula', 'Nombre']
    for evento in eventos:
        fecha_str = ''
        if 'fecha_inicio' in evento and evento['fecha_inicio']:
            if isinstance(evento['fecha_inicio'], str):
                # Si es string, intentar convertir a datetime
                try:
                    fecha = datetime.strptime(evento['fecha_inicio'], '%Y-%m-%d')
                    fecha_str = fecha.strftime('%d/%m/%y')
                except (ValueError, TypeError):
                    fecha_str = 'Fecha no disponible'
            elif isinstance(evento['fecha_inicio'], datetime):
                # Si ya es un objeto datetime
                fecha_str = evento['fecha_inicio'].strftime('%d/%m/%y')
        
        header.append(f"{evento['codigo']} ({fecha_str})")
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