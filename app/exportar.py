from flask import Blueprint, render_template, request, flash, redirect, url_for, session, send_file
from app import db, collection_eventos, collection_participantes
from pymongo import MongoClient
from config import config
from datetime import datetime
from flask_login import login_required, current_user
import csv
import io

exportar_bp = Blueprint('exportar', __name__)


###
### Exportar eventos y participantes
###
@exportar_bp.route('/exportar', methods=['GET', 'POST'])
@login_required
def exportar_eventos():
    if request.method == 'POST':
        codigo_evento = request.form.get('codigo_evento')
        tipo_exportacion = request.form.get('tipo_exportacion')
        
        if not codigo_evento:
            flash('Debe seleccionar un evento', 'error')
            return redirect(url_for('exportar.exportar_eventos'))
            
        # Obtener los datos del evento
        evento = collection_eventos.find_one({'codigo': codigo_evento})
        if not evento:
            flash('Evento no encontrado', 'error')
            return redirect(url_for('exportar.exportar_eventos'))
        
        # Crear un buffer en memoria para el archivo CSV
        output = io.StringIO()
        writer = csv.writer(output)
        
        if tipo_exportacion == 'evento':
            # Exportar datos del evento
            headers = ['afiche', 'afiche_750', 'autor', 'carga_horaria', 'certificado', 
                      'codigo', 'cupos', 'descripcion', 'estado_evento', 'fecha_fin', 
                      'fecha_inicio', 'fondo', 'lugar', 'modalidad', 'nombre', 
                      'programa', 'tipo', 'unidad_ejecutora']
            writer.writerow(headers)
            row = [evento.get(field, '') for field in headers]
            writer.writerow(row)
            nombre_archivo = f'evento_{codigo_evento}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            
        else:  # tipo_exportacion == 'participantes'
            # Exportar datos de participantes
            headers = ['apellidos', 'nombres', 'cedula', 'codigo_evento', 'indice_registro', 
                      'nanoid', 'perfil', 'region', 'rol', 'timestamp', 
                      'tipo_evento', 'unidad']
            writer.writerow(headers)
            
            # Obtener todos los participantes del evento
            participantes = collection_participantes.find({'codigo_evento': codigo_evento})
            for participante in participantes:
                row = [participante.get(field, '') for field in headers]
                writer.writerow(row)
            nombre_archivo = f'participantes_{codigo_evento}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        
        # Preparar el archivo para descarga
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=nombre_archivo
        )
    
    # Si es GET, mostrar el formulario
    eventos = collection_eventos.find({}, {'codigo': 1, 'nombre': 1})
    return render_template('exportar.html', eventos=eventos)
            