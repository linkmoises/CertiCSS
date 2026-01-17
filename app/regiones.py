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
### 1 - Bocas Del Toro
###
@regiones_bp.route('/tablero/eventos/bocas-del-toro')
@regiones_bp.route('/tablero/eventos/bocas-del-toro/page/<int:page>')
@login_required
def eventos_region_bocas(page=1):
    titulo_region = "Bocas Del Toro"
    eventos_por_pagina = 20

    # Filtro para excluir eventos con registro abierto y sesiones docentes
    filtro_eventos = {
        'region': "bocasdeltoro",
        'registro_abierto': {'$ne': True},
        'tipo': {'$ne': 'Sesión Docente'}
    }

    # Calcular el número total de eventos
    total_eventos = collection_eventos.count_documents(filtro_eventos)
    # Calcular el número total de páginas
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondear hacia arriba

    # Obtener los eventos para la página actual
    eventos_cursor = collection_eventos.find(filtro_eventos).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
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
### 2 - Coclé
###
@regiones_bp.route('/tablero/eventos/cocle')
@regiones_bp.route('/tablero/eventos/cocle/page/<int:page>')
@login_required
def eventos_region_cocle(page=1):
    titulo_region = "Coclé"
    eventos_por_pagina = 20

    # Filtro para excluir eventos con registro abierto y sesiones docentes
    filtro_eventos = {
        'region': "cocle",
        'registro_abierto': {'$ne': True},
        'tipo': {'$ne': 'Sesión Docente'}
    }

    # Calcular el número total de eventos
    total_eventos = collection_eventos.count_documents(filtro_eventos)
    # Calcular el número total de páginas
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondear hacia arriba

    # Obtener los eventos para la página actual
    eventos_cursor = collection_eventos.find(filtro_eventos).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
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

    # Filtro para excluir eventos con registro abierto y sesiones docentes
    filtro_eventos = {
        'region': "colon",
        'registro_abierto': {'$ne': True},
        'tipo': {'$ne': 'Sesión Docente'}
    }

    # Calcular el número total de eventos
    total_eventos = collection_eventos.count_documents(filtro_eventos)
    # Calcular el número total de páginas
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondear hacia arriba

    # Obtener los eventos para la página actual
    eventos_cursor = collection_eventos.find(filtro_eventos).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
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

    # Filtro para excluir eventos con registro abierto y sesiones docentes
    filtro_eventos = {
        'region': "chiriqui",
        'registro_abierto': {'$ne': True},
        'tipo': {'$ne': 'Sesión Docente'}
    }

    # Calcular el número total de eventos
    total_eventos = collection_eventos.count_documents(filtro_eventos)
    # Calcular el número total de páginas
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondear hacia arriba

    # Obtener los eventos para la página actual
    eventos_cursor = collection_eventos.find(filtro_eventos).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
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
### 5 - Darién
### No tiene unidades ejecutoras de CSS * julio 2025
###


###
### 6 - Herrera
###
@regiones_bp.route('/tablero/eventos/herrera')
@regiones_bp.route('/tablero/eventos/herrera/page/<int:page>')
@login_required
def eventos_region_herrera(page=1):
    titulo_region = "Herrera"
    eventos_por_pagina = 20

    # Filtro para excluir eventos con registro abierto y sesiones docentes
    filtro_eventos = {
        'region': "herrera",
        'registro_abierto': {'$ne': True},
        'tipo': {'$ne': 'Sesión Docente'}
    }

    # Calcular el número total de eventos
    total_eventos = collection_eventos.count_documents(filtro_eventos)
    # Calcular el número total de páginas
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondear hacia arriba

    # Obtener los eventos para la página actual
    eventos_cursor = collection_eventos.find(filtro_eventos).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
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
### 7 - Los Santos
###
@regiones_bp.route('/tablero/eventos/los-santos')
@regiones_bp.route('/tablero/eventos/los-santos/page/<int:page>')
@login_required
def eventos_region_los_santos(page=1):
    titulo_region = "Los Santos"
    eventos_por_pagina = 20

    # Filtro para excluir eventos con registro abierto y sesiones docentes
    filtro_eventos = {
        'region': "lossantos",
        'registro_abierto': {'$ne': True},
        'tipo': {'$ne': 'Sesión Docente'}
    }

    # Calcular el número total de eventos
    total_eventos = collection_eventos.count_documents(filtro_eventos)
    # Calcular el número total de páginas
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondear hacia arriba

    # Obtener los eventos para la página actual
    eventos_cursor = collection_eventos.find(filtro_eventos).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
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
### 8 - Panamá (Incluye Panamá Metro, Este y San Miguelito)
###
@regiones_bp.route('/tablero/eventos/panama')
@regiones_bp.route('/tablero/eventos/panama/page/<int:page>')
@login_required
def eventos_region_panama(page=1):
    titulo_region = "Panamá"
    eventos_por_pagina = 20

    # Filtro para excluir eventos con registro abierto y sesiones docentes
    filtro_eventos = {
        'region': {"$in": ["panama", "sanmiguelito", "panamaeste"]},
        'registro_abierto': {'$ne': True},
        'tipo': {'$ne': 'Sesión Docente'}
    }

    # Calcular el número total de eventos
    total_eventos = collection_eventos.count_documents(filtro_eventos)
    # Calcular el número total de páginas
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondear hacia arriba

    # Obtener los eventos para la página actual
    eventos_cursor = collection_eventos.find(filtro_eventos).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
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
### 9 - Veraguas
###
@regiones_bp.route('/tablero/eventos/veraguas')
@regiones_bp.route('/tablero/eventos/veraguas/page/<int:page>')
@login_required
def eventos_region_veraguas(page=1):
    titulo_region = "Veraguas"
    eventos_por_pagina = 20

    # Filtro para excluir eventos con registro abierto y sesiones docentes
    filtro_eventos = {
        'region': "veraguas",
        'registro_abierto': {'$ne': True},
        'tipo': {'$ne': 'Sesión Docente'}
    }

    # Calcular el número total de eventos
    total_eventos = collection_eventos.count_documents(filtro_eventos)
    # Calcular el número total de páginas
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondear hacia arriba

    # Obtener los eventos para la página actual
    eventos_cursor = collection_eventos.find(filtro_eventos).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
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
### 13 - Panamá Oeste
###
@regiones_bp.route('/tablero/eventos/panama-oeste')
@regiones_bp.route('/tablero/eventos/panama-oeste/page/<int:page>')
@login_required
def eventos_region_panamaoeste(page=1):
    titulo_region = "Panamá Oeste"
    eventos_por_pagina = 20

    # Filtro para excluir eventos con registro abierto y sesiones docentes
    filtro_eventos = {
        'region': "panamaoeste",
        'registro_abierto': {'$ne': True},
        'tipo': {'$ne': 'Sesión Docente'}
    }

    # Calcular el número total de eventos
    total_eventos = collection_eventos.count_documents(filtro_eventos)
    # Calcular el número total de páginas
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondear hacia arriba

    # Obtener los eventos para la página actual
    eventos_cursor = collection_eventos.find(filtro_eventos).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
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
### Subregión - Panamá Este
###
@regiones_bp.route('/tablero/eventos/panama-este')
@regiones_bp.route('/tablero/eventos/panama-este/page/<int:page>')
@login_required
def eventos_region_panamaeste(page=1):
    titulo_region = "Panamá Este"
    eventos_por_pagina = 20

    # Filtro para excluir eventos con registro abierto y sesiones docentes
    filtro_eventos = {
        'region': "panamaeste",
        'registro_abierto': {'$ne': True},
        'tipo': {'$ne': 'Sesión Docente'}
    }

    # Calcular el número total de eventos
    total_eventos = collection_eventos.count_documents(filtro_eventos)
    # Calcular el número total de páginas
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondear hacia arriba

    # Obtener los eventos para la página actual
    eventos_cursor = collection_eventos.find(filtro_eventos).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
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
### Subregión - San Miguelito
###
@regiones_bp.route('/tablero/eventos/san-miguelito')
@regiones_bp.route('/tablero/eventos/san-miguelito/page/<int:page>')
@login_required
def eventos_region_sanmiguelito(page=1):
    titulo_region = "San Miguelito"
    eventos_por_pagina = 20

    # Filtro para excluir eventos con registro abierto y sesiones docentes
    filtro_eventos = {
        'region': "sanmiguelito",
        'registro_abierto': {'$ne': True},
        'tipo': {'$ne': 'Sesión Docente'}
    }

    # Calcular el número total de eventos
    total_eventos = collection_eventos.count_documents(filtro_eventos)
    # Calcular el número total de páginas
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondear hacia arriba

    # Obtener los eventos para la página actual
    eventos_cursor = collection_eventos.find(filtro_eventos).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
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
### Subregión - Panamá Metro
###
@regiones_bp.route('/tablero/eventos/panama-metro')
@regiones_bp.route('/tablero/eventos/panama-metro/page/<int:page>')
@login_required
def eventos_region_panamametro(page=1):
    titulo_region = "Panamá Metro"
    eventos_por_pagina = 20

    # Filtro para excluir eventos con registro abierto y sesiones docentes
    filtro_eventos = {
        'region': "panama",
        'registro_abierto': {'$ne': True},
        'tipo': {'$ne': 'Sesión Docente'}
    }

    # Calcular el número total de eventos
    total_eventos = collection_eventos.count_documents(filtro_eventos)
    # Calcular el número total de páginas
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondear hacia arriba

    # Obtener los eventos para la página actual
    eventos_cursor = collection_eventos.find(filtro_eventos).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
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