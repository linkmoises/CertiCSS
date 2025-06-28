from flask import Blueprint, render_template, request, flash, redirect, url_for, session, send_file
from app import db, collection_eventos, collection_participantes
from pymongo import MongoClient
from config import config
from datetime import datetime
from flask_login import login_required, current_user
import csv
import io
from app.utils.agregar_nanoid import generate_nanoid

importar_bp = Blueprint('importar', __name__)


###
### Importar eventos y participantes
###
@importar_bp.route('/bases-de-datos/importar', methods=['GET', 'POST'])
@login_required
def importar_eventos():
    if request.method == 'POST':
        archivo = request.files['archivo']
        tipo_importacion = request.form.get('tipo_importacion')
        
        if not archivo:
            flash('Debe seleccionar un archivo', 'error')
            return redirect(url_for('importar.importar_eventos'))
            
        try:
            # Leer el archivo CSV
            archivo_csv = io.StringIO(archivo.read().decode('utf-8'))
            reader = csv.DictReader(archivo_csv)
            
            if tipo_importacion == 'evento':
                # Importar evento
                for row in reader:
                    codigo_evento = row.get('codigo')
                    if not codigo_evento:
                        continue
                        
                    # Verificar si el evento ya existe
                    evento_existente = collection_eventos.find_one({'codigo': codigo_evento})
                    if evento_existente:
                        flash(f'El evento con código {codigo_evento} ya existe y no será importado', 'warning')
                        continue
                    
                    # Convertir campos vacíos a None
                    for key in row:
                        if row[key] == '':
                            row[key] = None
                    
                    # Insertar el nuevo evento
                    collection_eventos.insert_one(row)
                    flash(f'Evento {codigo_evento} importado exitosamente', 'success')
                    
            else:  # tipo_importacion == 'participantes'
                # Importar participantes
                participantes_importados = 0
                participantes_omitidos = 0
                
                for row in reader:
                    codigo_evento = row.get('codigo_evento')
                    cedula = row.get('cedula')
                    
                    if not codigo_evento or not cedula:
                        continue
                    
                    # Verificar si el participante ya existe
                    participante_existente = collection_participantes.find_one({
                        'codigo_evento': codigo_evento,
                        'cedula': cedula
                    })
                    
                    if participante_existente:
                        participantes_omitidos += 1
                        continue
                    
                    # Convertir campos vacíos a None
                    for key in row:
                        if row[key] == '':
                            row[key] = None
                    
                    # Generar nanoid si no viene en el CSV
                    if not row.get('nanoid') or not row['nanoid']:
                        # Si hay título de ponencia, usarlo, si no, None
                        titulo_ponencia = row.get('titulo_ponencia')
                        row['nanoid'] = generate_nanoid(cedula, codigo_evento, titulo_ponencia)
                    
                    # Insertar el nuevo participante
                    collection_participantes.insert_one(row)
                    participantes_importados += 1
                
                flash(f'Importación completada: {participantes_importados} participantes importados, {participantes_omitidos} omitidos', 'success')
            
            return redirect(url_for('importar.importar_eventos'))
            
        except Exception as e:
            flash(f'Error al importar el archivo: {str(e)}', 'error')
            return redirect(url_for('importar.importar_eventos'))
    
    return render_template('importar.html')
