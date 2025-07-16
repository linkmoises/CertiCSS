###
###
###  Este archivo contiene las rutas y funciones relacionadas con la visualización de 
###  eventos según provincias
### 
###
###
from flask import Flask, Blueprint, render_template, render_template_string, send_file, request, redirect, url_for
from app import db, collection_eventos, collection_participantes
from flask_login import login_required, current_user
from datetime import datetime

regiones_bp = Blueprint('regiones', __name__)


###
### Mapa de eventos
###
@regiones_bp.route('/tablero/eventos/mapa')
@login_required
def eventos_region():
    return render_template('eventos-mapa.html')


###
###
###
@regiones_bp.route('/tablero/eventos/bocas-del-toro')
@regiones_bp.route('/tablero/eventos/bocas-del-toro/page/<int:page>')
@login_required
def eventos_region_bocas(page=1):
    titulo_region = "Bocas Del Toro"
    eventos_por_pagina = 20

    # Calcular el número total de eventos
    total_eventos = collection_eventos.count_documents({"region": "bocasdeltoro"})
    # Calcular el número total de páginas
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondear hacia arriba

    # Obtener los eventos para la página actual
    eventos_cursor = collection_eventos.find({"region": "bocasdeltoro"}).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
    eventos = list(eventos_cursor)

    # Verificar si el usuario es organizador en cada evento
    for evento in eventos:
        es_organizador = collection_participantes.find_one({
            "codigo_evento": evento["codigo"],
            "cedula": str(current_user.cedula),
            "rol": "coorganizador"
        }) is not None 

        evento["es_organizador"] = es_organizador

    return render_template('eventos-provincias.html',
        eventos=eventos,
        page=page,
        titulo_region=titulo_region,
        total_paginas=total_paginas,
        total_eventos=total_eventos
    )


###
### 3 - Colón
###
@regiones_bp.route('/tablero/eventos/colon')
@regiones_bp.route('/tablero/eventos/colon/page/<int:page>')
@login_required
def eventos_region_colon(page=1):
    titulo_region = "Colón"
    eventos_por_pagina = 20

    # Calcular el número total de eventos
    total_eventos = collection_eventos.count_documents({"region": "colon"})
    # Calcular el número total de páginas
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondear hacia arriba

    # Obtener los eventos para la página actual
    eventos_cursor = collection_eventos.find({"region": "colon"}).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
    eventos = list(eventos_cursor)

    # Verificar si el usuario es organizador en cada evento
    for evento in eventos:
        es_organizador = collection_participantes.find_one({
            "codigo_evento": evento["codigo"],
            "cedula": str(current_user.cedula),
            "rol": "coorganizador"
        }) is not None 

        evento["es_organizador"] = es_organizador

    return render_template('eventos-provincias.html',
        eventos=eventos,
        page=page,
        titulo_region=titulo_region,
        total_paginas=total_paginas,
        total_eventos=total_eventos
    )


###
### 4 - Chiriquí
###
@regiones_bp.route('/tablero/eventos/chiriqui')
@regiones_bp.route('/tablero/eventos/chiriqui/page/<int:page>')
@login_required
def eventos_region_chiriqui(page=1):
    titulo_region = "Chiriquí"
    eventos_por_pagina = 20

    # Calcular el número total de eventos
    total_eventos = collection_eventos.count_documents({"region": "chiriqui"})
    # Calcular el número total de páginas
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondear hacia arriba

    # Obtener los eventos para la página actual
    eventos_cursor = collection_eventos.find({"region": "chiriqui"}).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
    eventos = list(eventos_cursor)

    # Verificar si el usuario es organizador en cada evento
    for evento in eventos:
        es_organizador = collection_participantes.find_one({
            "codigo_evento": evento["codigo"],
            "cedula": str(current_user.cedula),
            "rol": "coorganizador"
        }) is not None 

        evento["es_organizador"] = es_organizador

    return render_template('eventos-provincias.html',
        eventos=eventos,
        page=page,
        titulo_region=titulo_region,
        total_paginas=total_paginas,
        total_eventos=total_eventos
    )