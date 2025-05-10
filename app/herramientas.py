from flask import Blueprint, render_template, url_for
from datetime import datetime
from app import collection_eventos, BASE_URL

herramientas_bp = Blueprint('herramientas', __name__)


###
### Función para el carrusel de eventos
###
@herramientas_bp.route('/carrusel')
def carrusel():
    # Obtener la fecha de inicio del día actual
    inicio_hoy = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Consultar los eventos futuros
    eventos_futuros = collection_eventos.find({
        "fecha_inicio": {"$gte": inicio_hoy},
        "estado_evento": {"$ne": "borrador"}
    }).sort("fecha_inicio").limit(5)
    
    # Preparar las imágenes para el carrusel
    carousel_images = []

    for evento in eventos_futuros:
        afiche_evento = evento.get("afiche_evento")
        if not afiche_evento:
            afiche_evento = url_for('static', filename='assets/afiche-generico.jpg')
        else:
            afiche_evento = f"{BASE_URL}{afiche_evento}"
        
        afiche_evento_750 = evento.get("afiche_evento_750")
        if not afiche_evento_750:
            afiche_evento_750 = url_for('static', filename='assets/afiche-generico.jpg')
        else:
            afiche_evento_750 = f"{BASE_URL}{afiche_evento_750}"

        carousel_images.append({
            "id": evento.get("codigo", ""),
            "afiche": evento.get("afiche", ""),
            "afiche_thumb": evento.get("afiche_750", ""),
            "alt": evento.get("nombre", "Evento sin nombre")
        })

    return render_template('carrusel.html', carousel_images=carousel_images)


###
### Función para el temporizador
###
@herramientas_bp.route('/temporizador')
def temporizador():
    return render_template('temporizador.html') 