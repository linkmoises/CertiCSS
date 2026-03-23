from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from datetime import datetime
from bson import ObjectId
import math

analisis_bp = Blueprint('analisis', __name__)

from app import collection_eventos, collection_participantes

def puede_editar_analisis(evento):
    if not evento:
        return False
    
    if evento.get('estado_evento') == 'cerrado':
        return False
    
    if evento.get('estado_evento') != 'publicado':
        return False
    
    fecha_fin = evento.get('fecha_fin')
    if fecha_fin and isinstance(fecha_fin, datetime):
        if fecha_fin > datetime.now():
            return False
    else:
        return False
    
    es_autor = str(current_user.id) == str(evento.get('autor'))
    es_coorganizador = collection_participantes.find_one({
        'codigo_evento': evento.get('codigo'),
        'cedula': str(current_user.cedula),
        'rol': 'coorganizador'
    }) is not None
    
    return es_autor or es_coorganizador


@analisis_bp.route('/tablero/metricas/<codigo_evento>/analisis', methods=['GET', 'POST'])
@login_required
def analisis_evento(codigo_evento):
    evento = collection_eventos.find_one({'codigo': codigo_evento})
    
    if not evento:
        flash('Evento no encontrado', 'error')
        return redirect(url_for('mis_metricas'))
    
    puede_editar = puede_editar_analisis(evento)
    
    swot_data = evento.get('swot', {})
    incidences = evento.get('incidencias', [])
    
    if request.method == 'POST':
        if not puede_editar:
            flash('No tienes permisos para editar este análisis', 'error')
            return redirect(url_for('analisis.analisis_evento', codigo_evento=codigo_evento))
        
        fortalezas = request.form.get('fortalezas', '').strip()
        oportunidades = request.form.get('oportunidades', '').strip()
        debilidades = request.form.get('debilidades', '').strip()
        amenazas = request.form.get('amenazas', '').strip()
        
        nuevas_incidencias = []
        if 'incidencia_tipo' in request.form:
            tipos = request.form.getlist('incidencia_tipo')
            descripciones = request.form.getlist('incidencia_descripcion')
            fechas = request.form.getlist('incidencia_fecha')
            
            for i in range(len(tipos)):
                if tipos[i] and descripciones[i].strip():
                    nuevas_incidencias.append({
                        'tipo': tipos[i],
                        'descripcion': descripciones[i].strip(),
                        'fecha': fechas[i] if fechas[i] else datetime.now().strftime('%Y-%m-%d'),
                        'creado_por': current_user.id,
                        'creado_en': datetime.now()
                    })
        
        actualizar = {
            'fortalezas': fortalezas,
            'oportunidades': oportunidades,
            'debilidades': debilidades,
            'amenazas': amenazas,
            'swot': {
                'fortalezas': fortalezas,
                'oportunidades': oportunidades,
                'debilidades': debilidades,
                'amenazas': amenazas,
                'actualizado_por': current_user.id,
                'actualizado_en': datetime.now()
            },
            'incidencias': nuevas_incidencias
        }
        
        collection_eventos.update_one(
            {'codigo': codigo_evento},
            {'$set': actualizar}
        )
        
        flash('Análisis guardado correctamente', 'success')
        return redirect(url_for('analisis.analisis_evento', codigo_evento=codigo_evento))
    
    return render_template(
        'analisis_evento.html',
        evento=evento,
        swot=swot_data,
        incidences=incidences,
        puede_editar=puede_editar,
        active_section='metricas'
    )