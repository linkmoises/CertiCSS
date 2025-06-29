###
###
###  Este archivo contiene las rutas y funciones relacionadas con la normalización de los nombres
###  en la base de datos y el buscador avanzado.
### 
###
###
from flask import Flask, Blueprint, render_template, render_template_string, send_file, request, redirect, url_for
from app import db, collection_participantes
from flask_login import login_required

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