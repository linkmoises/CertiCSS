###
###
###  Este archivo contiene las rutas y funciones relacionadas con la normalización de los nombres
###  en la base de datos y el buscador avanzado.
### 
###
###
from flask import Flask, Blueprint, render_template, flash, render_template_string, send_file, request, redirect, url_for
from app import db, collection_participantes, collection_eventos, collection_usuarios
from flask_login import login_required, current_user
from bson.objectid import ObjectId

normalizador_bp = Blueprint('normalizador', __name__)


###
### Búsqueda avanzada
###
@normalizador_bp.route('/tablero/busqueda-avanzada', methods=['GET', 'POST'])
@login_required
def busqueda_avanzada():
    if request.method == 'POST':
        termino_busqueda = request.form.get('termino_busqueda', '').strip()
        # Redirigir con el término de búsqueda como parámetro GET
        return redirect(url_for('normalizador.busqueda_avanzada', q=termino_busqueda))
    
    # Obtener el término de búsqueda desde parámetros GET
    termino_busqueda = request.args.get('q', '').strip()
    resultados = []
    total_resultados = 0
    
    def resaltar_termino(texto, termino):
        """Resalta el término de búsqueda en el texto dado"""
        if not texto or not termino:
            return texto or 'N/A'
        
        import re
        # Escapar caracteres especiales del término de búsqueda
        termino_escaped = re.escape(termino)
        # Reemplazar con el término resaltado
        texto_resaltado = re.sub(
            f'({termino_escaped})', 
            r'<mark class="bg-yellow-200 px-1 rounded">\1</mark>', 
            str(texto), 
            flags=re.IGNORECASE
        )
        return texto_resaltado
    
    if termino_busqueda:
        # Crear consulta para buscar en múltiples campos
        from bson.regex import Regex
        import re
        
        # Buscar en múltiples campos usando regex case-insensitive
        query = {
            "$or": [
                {"nombres": {"$regex": re.escape(termino_busqueda), "$options": "i"}},
                {"apellidos": {"$regex": re.escape(termino_busqueda), "$options": "i"}},
                {"cedula": {"$regex": re.escape(termino_busqueda), "$options": "i"}},
                {"nanoid": {"$regex": re.escape(termino_busqueda), "$options": "i"}},
                {"rol": {"$regex": re.escape(termino_busqueda), "$options": "i"}},
                {"codigo_evento": {"$regex": re.escape(termino_busqueda), "$options": "i"}}
            ]
        }
        
        # Ejecutar la búsqueda
        resultados = list(collection_participantes.find(query).limit(100))  # Limitar a 100 resultados
        total_resultados = len(resultados)
    
    return render_template('busqueda_avanzada.html', 
                         resultados=resultados, 
                         total_resultados=total_resultados,
                         termino_busqueda=termino_busqueda,
                         resaltar_termino=resaltar_termino) 


@normalizador_bp.route('/tablero/normalizador', methods=['GET', 'POST'])
@login_required
def normalizador():
    # Verificar si el usuario es administrador
    if current_user.rol != 'administrador':
        #log_event(f"Usuario [{current_user.email}] intentó ingresar al normalizador.")
        return redirect(url_for('normalizador.busqueda_avanzada'))

    participante = None
    registros_encontrados = []
    mensaje = ""
    tipo_mensaje = ""
    
    if request.method == 'POST':
        cedula = request.form.get('cedula', '').strip()
        
        if cedula:
            # Buscar todos los registros de la cédula en la colección participantes
            registros_encontrados = list(collection_participantes.find({"cedula": cedula}))
            
            if registros_encontrados:
                # Tomar el primer registro como referencia para mostrar en el formulario
                participante = registros_encontrados[0]
                mensaje = f"Se encontraron {len(registros_encontrados)} registros para la cédula {cedula}"
                tipo_mensaje = "success"
            else:
                mensaje = f"No se encontraron registros para la cédula {cedula}"
                tipo_mensaje = "error"
        
        # Si se envió el formulario de corrección
        if 'corregir' in request.form:
            cedula_corregir = request.form.get('cedula_corregir')
            nombres_corregidos = request.form.get('nombres_corregidos', '').strip()
            apellidos_corregidos = request.form.get('apellidos_corregidos', '').strip()
            
            if cedula_corregir and (nombres_corregidos or apellidos_corregidos):
                # Actualizar todos los registros de esa cédula
                update_data = {}
                if nombres_corregidos:
                    update_data['nombres'] = nombres_corregidos
                if apellidos_corregidos:
                    update_data['apellidos'] = apellidos_corregidos
                
                # Actualizar todos los registros de la cédula
                result = collection_participantes.update_many(
                    {"cedula": cedula_corregir},
                    {"$set": update_data}
                )
                
                if result.modified_count > 0:
                    mensaje = f"Se corrigieron {result.modified_count} registros exitosamente"
                    tipo_mensaje = "success"
                    # Limpiar los registros para mostrar el estado actualizado
                    registros_encontrados = list(collection_participantes.find({"cedula": cedula_corregir}))
                    if registros_encontrados:
                        participante = registros_encontrados[0]
                else:
                    mensaje = "No se pudieron actualizar los registros"
                    tipo_mensaje = "error"
            else:
                mensaje = "Debe proporcionar al menos nombres o apellidos para corregir"
                tipo_mensaje = "error"
    
    return render_template('normalizador.html', 
                         participante=participante,
                         registros_encontrados=registros_encontrados,
                         mensaje=mensaje,
                         tipo_mensaje=tipo_mensaje)


@normalizador_bp.route('/tablero/busqueda-eventos', methods=['GET', 'POST'])
@login_required
def buscar_eventos():
    if request.method == 'POST':
        termino = request.form.get('termino_busqueda', '').strip()
        region = request.form.get('region', '').strip()
        tipo = request.form.get('tipo', '').strip()
        modalidad = request.form.get('modalidad', '').strip()
        estado = request.form.get('estado', '').strip()
        return redirect(url_for('normalizador.buscar_eventos',
                                q=termino, region=region, tipo=tipo,
                                modalidad=modalidad, estado=estado))

    termino = request.args.get('q', '').strip()
    filtro_region = request.args.get('region', '').strip()
    filtro_tipo = request.args.get('tipo', '').strip()
    filtro_modalidad = request.args.get('modalidad', '').strip()
    filtro_estado = request.args.get('estado', '').strip()
    resultados = []
    total_resultados = 0

    def resaltar_termino(texto, termino_busqueda):
        if not texto or not termino_busqueda:
            return texto or 'N/A'
        import re
        termino_escaped = re.escape(termino_busqueda)
        texto_resaltado = re.sub(
            f'({termino_escaped})',
            r'<mark class="bg-yellow-200 px-1 rounded">\1</mark>',
            str(texto),
            flags=re.IGNORECASE
        )
        return texto_resaltado

    if termino or filtro_region or filtro_tipo or filtro_modalidad or filtro_estado:
        import re

        query = {}

        if termino:
            query["$or"] = [
                {"nombre": {"$regex": re.escape(termino), "$options": "i"}},
                {"codigo": {"$regex": re.escape(termino), "$options": "i"}},
                {"region": {"$regex": re.escape(termino), "$options": "i"}},
                {"unidad_ejecutora": {"$regex": re.escape(termino), "$options": "i"}},
                {"lugar": {"$regex": re.escape(termino), "$options": "i"}},
                {"tipo": {"$regex": re.escape(termino), "$options": "i"}},
                {"modalidad": {"$regex": re.escape(termino), "$options": "i"}},
                {"descripcion": {"$regex": re.escape(termino), "$options": "i"}},
            ]

        if filtro_region:
            query["region"] = filtro_region
        if filtro_tipo:
            query["tipo"] = filtro_tipo
        if filtro_modalidad:
            query["modalidad"] = filtro_modalidad
        if filtro_estado:
            query["estado_evento"] = filtro_estado

        resultados = list(collection_eventos.find(query).sort("fecha_inicio", -1).limit(100))
        total_resultados = len(resultados)

        participantes_col = collection_participantes
        usuarios_col = collection_usuarios
        for evento in resultados:
            evento["es_organizador"] = participantes_col.find_one({
                "codigo_evento": evento["codigo"],
                "cedula": str(current_user.cedula),
                "rol": "coorganizador"
            }) is not None
            if evento.get("autor"):
                evento["autor_info"] = usuarios_col.find_one(
                    {"_id": ObjectId(evento["autor"])},
                    {"nombres": 1, "apellidos": 1, "foto": 1}
                )

    return render_template('buscar_eventos.html',
                         resultados=resultados,
                         total_resultados=total_resultados,
                         termino_busqueda=termino,
                         filtro_region=filtro_region,
                         filtro_tipo=filtro_tipo,
                         filtro_modalidad=filtro_modalidad,
                         filtro_estado=filtro_estado,
                         resaltar_termino=resaltar_termino)