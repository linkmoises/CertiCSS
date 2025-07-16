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

catalogo_bp = Blueprint('catalogo', __name__)


###
### Mapa de eventos
###
@catalogo_bp.route('/catalogo/regiones')
def catalogo_region():
    return render_template('catalogo_mapa.html')


###
### 1 - Bocas Del Toro
###
@catalogo_bp.route('/catalogo/bocas-del-toro')
@catalogo_bp.route('/catalogo/bocas-del-toro/page/<int:page>')
def catalogo_region_bocas(page=1):
    titulo_region = "Bocas Del Toro"
    per_page = 15  # Número máximo de eventos por página
    skip = (page - 1) * per_page

    total_eventos = collection_eventos.count_documents({"region": "bocasdeltoro"})
    total_pages = (total_eventos + per_page - 1) // per_page  # Calcular el total de páginas

    # Obtener eventos paginados
    eventos = list(collection_eventos.find(
        {"region": "bocasdeltoro", "estado_evento": {"$ne": "borrador"}}
    ).sort("fecha_inicio", -1).skip(skip).limit(per_page))

    return render_template('catalogo_region.html',
        eventos=eventos,
        page=page,
        titulo_region=titulo_region,
        total_pages=total_pages,
        total_eventos=total_eventos
    )


###
### 2 - Coclé
###
@catalogo_bp.route('/catalogo/cocle')
@catalogo_bp.route('/catalogo/cocle/page/<int:page>')
def catalogo_region_cocle(page=1):
    titulo_region = "Coclé"
    per_page = 15  # Número máximo de eventos por página
    skip = (page - 1) * per_page

    total_eventos = collection_eventos.count_documents({"region": "cocle"})
    total_pages = (total_eventos + per_page - 1) // per_page  # Calcular el total de páginas

    # Obtener eventos paginados
    eventos = list(collection_eventos.find(
        {"region": "cocle", "estado_evento": {"$ne": "borrador"}}
    ).sort("fecha_inicio", -1).skip(skip).limit(per_page))

    return render_template('catalogo_region.html',
        eventos=eventos,
        page=page,
        titulo_region=titulo_region,
        total_pages=total_pages,
        total_eventos=total_eventos
    )


###
### 3 - Colón
###
@catalogo_bp.route('/catalogo/colon')
@catalogo_bp.route('/catalogo/colon/page/<int:page>')
def catalogo_region_colon(page=1):
    titulo_region = "Colón"
    per_page = 15  # Número máximo de eventos por página
    skip = (page - 1) * per_page

    total_eventos = collection_eventos.count_documents({"region": "colon"})
    total_pages = (total_eventos + per_page - 1) // per_page  # Calcular el total de páginas

    # Obtener eventos paginados
    eventos = list(collection_eventos.find(
        {"region": "colon", "estado_evento": {"$ne": "borrador"}}
    ).sort("fecha_inicio", -1).skip(skip).limit(per_page))

    return render_template('catalogo_region.html',
        eventos=eventos,
        page=page,
        titulo_region=titulo_region,
        total_pages=total_pages,
        total_eventos=total_eventos
    )


###
### 4 - Chiriqui
###
@catalogo_bp.route('/catalogo/chiriqui')
@catalogo_bp.route('/catalogo/chiriqui/page/<int:page>')
def catalogo_region_chiriqui(page=1):
    titulo_region = "Chiriquí"
    per_page = 15  # Número máximo de eventos por página
    skip = (page - 1) * per_page

    total_eventos = collection_eventos.count_documents({"region": "chiriqui"})
    total_pages = (total_eventos + per_page - 1) // per_page  # Calcular el total de páginas

    # Obtener eventos paginados
    eventos = list(collection_eventos.find(
        {"region": "chiriqui", "estado_evento": {"$ne": "borrador"}}
    ).sort("fecha_inicio", -1).skip(skip).limit(per_page))

    return render_template('catalogo_region.html',
        eventos=eventos,
        page=page,
        titulo_region=titulo_region,
        total_pages=total_pages,
        total_eventos=total_eventos
    )


###
### 5 - Darién
### No tiene unidades ejecutoras de CSS * julio 2025
###


###
### 6 - Herrera
###
@catalogo_bp.route('/catalogo/herrera')
@catalogo_bp.route('/catalogo/herrera/page/<int:page>')
def catalogo_region_herrera(page=1):
    titulo_region = "Herrera"
    per_page = 15  # Número máximo de eventos por página
    skip = (page - 1) * per_page

    total_eventos = collection_eventos.count_documents({"region": "herrera"})
    total_pages = (total_eventos + per_page - 1) // per_page  # Calcular el total de páginas

    # Obtener eventos paginados
    eventos = list(collection_eventos.find(
        {"region": "herrera", "estado_evento": {"$ne": "borrador"}}
    ).sort("fecha_inicio", -1).skip(skip).limit(per_page))

    return render_template('catalogo_region.html',
        eventos=eventos,
        page=page,
        titulo_region=titulo_region,
        total_pages=total_pages,
        total_eventos=total_eventos
    )


###
### 7 - Los Santos
###
@catalogo_bp.route('/catalogo/los-santos')
@catalogo_bp.route('/catalogo/los-santos/page/<int:page>')
def catalogo_region_los_santos(page=1):
    titulo_region = "Los Santos"
    per_page = 15  # Número máximo de eventos por página
    skip = (page - 1) * per_page

    total_eventos = collection_eventos.count_documents({"region": "lossantos"})
    total_pages = (total_eventos + per_page - 1) // per_page  # Calcular el total de páginas

    # Obtener eventos paginados
    eventos = list(collection_eventos.find(
        {"region": "lossantos", "estado_evento": {"$ne": "borrador"}}
    ).sort("fecha_inicio", -1).skip(skip).limit(per_page))

    return render_template('catalogo_region.html',
        eventos=eventos,
        page=page,
        titulo_region=titulo_region,
        total_pages=total_pages,
        total_eventos=total_eventos
    )


###
### 9 - Veraguas
###
@catalogo_bp.route('/catalogo/verguas')
@catalogo_bp.route('/catalogo/veraguas/page/<int:page>')
def catalogo_region_veraguas(page=1):
    titulo_region = "Veraguas"
    per_page = 15  # Número máximo de eventos por página
    skip = (page - 1) * per_page

    total_eventos = collection_eventos.count_documents({"region": "veraguas"})
    total_pages = (total_eventos + per_page - 1) // per_page  # Calcular el total de páginas

    # Obtener eventos paginados
    eventos = list(collection_eventos.find(
        {"region": "veraguas", "estado_evento": {"$ne": "borrador"}}
    ).sort("fecha_inicio", -1).skip(skip).limit(per_page))

    return render_template('catalogo_region.html',
        eventos=eventos,
        page=page,
        titulo_region=titulo_region,
        total_pages=total_pages,
        total_eventos=total_eventos
    )


###
### 8 - Panamá
###
@catalogo_bp.route('/catalogo/panama')
@catalogo_bp.route('/catalogo/panama/page/<int:page>')
def catalogo_region_panama(page=1):
    titulo_region = "Panamá"
    per_page = 15  # Número máximo de eventos por página
    skip = (page - 1) * per_page

    total_eventos = collection_eventos.count_documents({"region": {"$in": ["panama", "sanmiguelito", "panamaeste"]}})
    total_pages = (total_eventos + per_page - 1) // per_page  # Calcular el total de páginas

    # Obtener eventos paginados
    eventos = list(collection_eventos.find(
        {"region": {"$in": ["panama", "sanmiguelito", "panamaeste"]}, "estado_evento": {"$ne": "borrador"}}
    ).sort("fecha_inicio", -1).skip(skip).limit(per_page))

    return render_template('catalogo_region.html',
        eventos=eventos,
        page=page,
        titulo_region=titulo_region,
        total_pages=total_pages,
        total_eventos=total_eventos
    )


###
### 13 - Panamá Oeste
###
@catalogo_bp.route('/catalogo/panama-oeste')
@catalogo_bp.route('/catalogo/panama-oeste/page/<int:page>')
def catalogo_region_panamaoeste(page=1):
    titulo_region = "Panamá Oeste"
    per_page = 15  # Número máximo de eventos por página
    skip = (page - 1) * per_page

    total_eventos = collection_eventos.count_documents({"region": "panamaoeste"})
    total_pages = (total_eventos + per_page - 1) // per_page  # Calcular el total de páginas

    # Obtener eventos paginados
    eventos = list(collection_eventos.find(
        {"region": "panamaoeste", "estado_evento": {"$ne": "borrador"}}
    ).sort("fecha_inicio", -1).skip(skip).limit(per_page))

    return render_template('catalogo_region.html',
        eventos=eventos,
        page=page,
        titulo_region=titulo_region,
        total_pages=total_pages,
        total_eventos=total_eventos
    )