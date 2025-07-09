from flask import Blueprint, render_template, request, flash, redirect, url_for, session, send_file
from app import db, collection_eventos, collection_participantes
from pymongo import MongoClient
from config import config
from datetime import datetime
from flask_login import login_required, current_user
import csv
import io
import os
import zipfile

exportar_bp = Blueprint('exportar', __name__)


###
### Exportar eventos y participantes
###
@exportar_bp.route('/tablero/bases-de-datos/exportar', methods=['GET', 'POST'])
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
        
        if tipo_exportacion == 'archivos':
            # Exportar archivos en ZIP
            return exportar_archivos_zip(evento)
        elif tipo_exportacion == 'evento':
            # Exportar datos del evento en CSV
            return exportar_evento_csv(evento)
        else:  # tipo_exportacion == 'participantes'
            # Exportar datos de participantes en CSV
            return exportar_participantes_csv(evento, codigo_evento)
    
    # Si es GET, mostrar el formulario
    eventos = collection_eventos.find({}, {'codigo': 1, 'nombre': 1})
    return render_template('exportar.html', eventos=eventos)


def listar_archivos_evento(codigo_evento):
    """Listar todos los archivos disponibles para un evento específico"""
    archivos_disponibles = []
    try:
        for archivo in os.listdir('static/uploads'):
            if archivo.startswith(codigo_evento):
                archivos_disponibles.append(archivo)
        return archivos_disponibles
    except Exception as e:
        print(f"[DEBUG] Error al listar archivos: {e}")
        return []


def exportar_archivos_zip(evento):
    """Exportar archivos del evento en formato ZIP"""
    # Crear un buffer en memoria para el archivo ZIP
    zip_buffer = io.BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        # Lista de campos de archivos a exportar
        campos_archivos = ['afiche_evento', 'fondo_evento', 'programa_evento', 'certificado_evento']
        
        archivos_agregados = 0
        archivos_encontrados = []
        archivos_no_encontrados = []
        
        for campo in campos_archivos:
            ruta_archivo = evento.get(campo)
            print(f"[DEBUG] Campo: {campo}, ruta_archivo: {ruta_archivo}")
            
            if ruta_archivo:
                # Extraer solo el nombre del archivo de la ruta
                nombre_archivo = os.path.basename(ruta_archivo)
                print(f"[DEBUG] Nombre del archivo extraído: {nombre_archivo}")
                
                # Construir la ruta completa del archivo
                # Si la ruta ya incluye 'static/uploads/', usarla directamente
                if ruta_archivo.startswith('static/uploads/'):
                    ruta_completa = ruta_archivo
                else:
                    # Si no, construir la ruta completa
                    ruta_completa = os.path.join('static', 'uploads', nombre_archivo)
                print(f"[DEBUG] Ruta completa: {ruta_completa}")
                
                # Verificar si el archivo existe
                if os.path.exists(ruta_completa):
                    try:
                        # Agregar el archivo al ZIP con el nombre original
                        zip_file.write(ruta_completa, nombre_archivo)
                        archivos_agregados += 1
                        archivos_encontrados.append(nombre_archivo)
                        print(f"[DEBUG] ✅ Archivo agregado exitosamente: {nombre_archivo}")
                    except Exception as e:
                        print(f"[DEBUG] ❌ Error al agregar archivo {ruta_completa}: {e}")
                        archivos_no_encontrados.append(f"{nombre_archivo} (error: {e})")
                else:
                    print(f"[DEBUG] ⚠️ Archivo no encontrado en ruta: {ruta_completa}")
                    archivos_no_encontrados.append(nombre_archivo)
                    
                    # Intentar buscar archivos con el código del evento como prefijo
                    codigo_evento = evento.get('codigo', '')
                    if codigo_evento:
                        print(f"[DEBUG] 🔍 Buscando archivos con prefijo: {codigo_evento}")
                        # Buscar archivos que coincidan con el patrón del código del evento
                        archivos_encontrados_por_prefijo = []
                        for archivo in os.listdir('static/uploads'):
                            if archivo.startswith(codigo_evento):
                                archivos_encontrados_por_prefijo.append(archivo)
                                # Intentar mapear el tipo de archivo
                                tipo_archivo = ""
                                if "afiche" in archivo.lower():
                                    tipo_archivo = "afiche"
                                elif "fondo" in archivo.lower():
                                    tipo_archivo = "fondo"
                                elif "programa" in archivo.lower():
                                    tipo_archivo = "programa"
                                elif "certificado" in archivo.lower():
                                    tipo_archivo = "certificado"
                                
                                # Si coincide con el tipo de archivo que estamos buscando
                                if tipo_archivo in campo.lower():
                                    ruta_alternativa = os.path.join('static', 'uploads', archivo)
                                    try:
                                        zip_file.write(ruta_alternativa, archivo)
                                        archivos_agregados += 1
                                        archivos_encontrados.append(archivo)
                                        print(f"[DEBUG] ✅ Archivo alternativo agregado: {archivo} (tipo: {tipo_archivo})")
                                        break
                                    except Exception as e:
                                        print(f"[DEBUG] ❌ Error al agregar archivo alternativo {ruta_alternativa}: {e}")
                                        archivos_no_encontrados.append(f"{archivo} (error: {e})")
                        
                        print(f"[DEBUG] Archivos encontrados con prefijo {codigo_evento}: {archivos_encontrados_por_prefijo}")
            else:
                print(f"[DEBUG] ⚠️ Campo {campo} está vacío o no existe")
        
        print(f"[DEBUG] 📊 Resumen:")
        print(f"[DEBUG] - Archivos agregados: {archivos_agregados}")
        print(f"[DEBUG] - Archivos encontrados: {archivos_encontrados}")
        print(f"[DEBUG] - Archivos no encontrados: {archivos_no_encontrados}")
        
        # Mostrar todos los archivos disponibles para este evento
        codigo_evento = evento.get('codigo', '')
        if codigo_evento:
            archivos_disponibles = listar_archivos_evento(codigo_evento)
            print(f"[DEBUG] - Todos los archivos disponibles para {codigo_evento}: {archivos_disponibles}")
            
            # Si no se encontraron archivos mapeados, agregar todos los disponibles
            if archivos_agregados == 0 and archivos_disponibles:
                print(f"[DEBUG] 🔄 No se encontraron archivos mapeados, agregando todos los disponibles")
                for archivo in archivos_disponibles:
                    ruta_archivo = os.path.join('static', 'uploads', archivo)
                    try:
                        zip_file.write(ruta_archivo, archivo)
                        archivos_agregados += 1
                        archivos_encontrados.append(archivo)
                        print(f"[DEBUG] ✅ Archivo agregado (fallback): {archivo}")
                    except Exception as e:
                        print(f"[DEBUG] ❌ Error al agregar archivo fallback {ruta_archivo}: {e}")
        
        if archivos_agregados == 0:
            flash('No se encontraron archivos para exportar. Verifique que los archivos existan en la carpeta uploads.', 'warning')
            return redirect(url_for('exportar.exportar_eventos'))
        else:
            # Mostrar información sobre los archivos exportados
            mensaje = f'Se exportaron {archivos_agregados} archivo(s): {", ".join(archivos_encontrados)}'
            if archivos_no_encontrados:
                mensaje += f'. Archivos no encontrados: {", ".join(archivos_no_encontrados)}'
            flash(mensaje, 'info')
    
    # Preparar el archivo ZIP para descarga
    zip_buffer.seek(0)
    nombre_archivo = f'archivos_{evento.get("codigo")}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip'
    
    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=nombre_archivo
    )


def exportar_evento_csv(evento):
    """Exportar datos del evento en formato CSV"""
    # Crear un buffer en memoria para el archivo CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Exportar datos del evento
    headers = ['afiche', 'afiche_750', 'autor', 'carga_horaria', 'certificado', 
              'codigo', 'cupos', 'descripcion', 'estado_evento', 'fecha_fin', 
              'fecha_inicio', 'fondo', 'lugar', 'modalidad', 'nombre', 
              'programa', 'tipo', 'unidad_ejecutora']
    writer.writerow(headers)
    row = [evento.get(field, '') for field in headers]
    writer.writerow(row)
    nombre_archivo = f'evento_{evento.get("codigo")}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    
    # Preparar el archivo para descarga
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=nombre_archivo
    )


def exportar_participantes_csv(evento, codigo_evento):
    """Exportar datos de participantes en formato CSV"""
    # Crear un buffer en memoria para el archivo CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Exportar datos de participantes
    headers = ['apellidos', 'nombres', 'cedula', 'codigo_evento', 'indice_registro', 
              'nanoid', 'perfil', 'region', 'rol', 'timestamp', 
              'tipo_evento', 'unidad']
    writer.writerow(headers)
    
    # Obtener todos los participantes del evento que tengan rol 'participante'
    participantes = collection_participantes.find({
        'codigo_evento': codigo_evento,
        'rol': 'participante'
    })
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