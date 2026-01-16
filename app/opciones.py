###
###
###  Este archivo contiene las rutas y funciones relacionadas con las opciones
###  globales de la plataforma
###
###
from flask import Blueprint, render_template, url_for, request, flash, redirect, Response
from app import collection_eventos, BASE_URL, db
from flask_login import login_required, current_user
from datetime import datetime
import csv
from io import StringIO
import os

opciones_bp = Blueprint('opciones', __name__)

# Colección para la planilla de funcionarios
collection_planilla = db['planilla']

def migrar_csv_a_mongodb():
    """Migra automáticamente el CSV existente a MongoDB si la colección está vacía"""
    try:
        # Verificar si ya hay datos en MongoDB
        if collection_planilla.count_documents({}) > 0:
            print("MongoDB ya contiene datos de funcionarios, no se requiere migración")
            return
        
        # Intentar cargar desde el archivo CSV existente
        csv_path = os.path.join(os.path.dirname(__file__), '..', 'static', 'assets', 'funcionarios-latest.csv')
        
        if not os.path.exists(csv_path):
            print(f"Instalación nueva detectada: No se encontró archivo CSV en {csv_path}")
            print("La base de datos de funcionarios está vacía. Use la interfaz web para cargar la primera planilla.")
            return
        
        cedulas_migradas = []
        timestamp = datetime.now()
        
        with open(csv_path, 'r', encoding='utf-8') as csvfile:
            csv_reader = csv.reader(csvfile)
            for row in csv_reader:
                if row and row[0].strip():
                    cedulas_migradas.append({
                        "cedula": row[0].strip(),
                        "timestamp": timestamp,
                        "accion": "migrado_csv",
                        "usuario": "sistema"
                    })
        
        if cedulas_migradas:
            collection_planilla.insert_many(cedulas_migradas)
            print(f"Migración completada: {len(cedulas_migradas)} cédulas migradas desde CSV a MongoDB")
        else:
            print("No se encontraron cédulas válidas en el archivo CSV")
            
    except Exception as e:
        print(f"Error durante la migración CSV a MongoDB: {e}")

# Ejecutar migración automática al importar el módulo
migrar_csv_a_mongodb()

@opciones_bp.route('/tablero/opciones')
@login_required
def opciones_globales():
    # Obtener estadísticas de la planilla actual
    total_funcionarios = collection_planilla.count_documents({})
    ultima_actualizacion = collection_planilla.find_one({}, sort=[("timestamp", -1)])
    
    return render_template('opciones_globales.html', 
                         total_funcionarios=total_funcionarios,
                         ultima_actualizacion=ultima_actualizacion)

@opciones_bp.route('/tablero/opciones/cargar-planilla', methods=['GET', 'POST'])
@login_required
def cargar_planilla():
    if request.method == 'POST':
        # Verificar que se subió un archivo
        if 'archivo_csv' not in request.files:
            flash('No se seleccionó ningún archivo.', 'error')
            return redirect(url_for('opciones.cargar_planilla'))
        
        archivo = request.files['archivo_csv']
        
        if archivo.filename == '':
            flash('No se seleccionó ningún archivo.', 'error')
            return redirect(url_for('opciones.cargar_planilla'))
        
        if not archivo.filename.lower().endswith('.csv'):
            flash('El archivo debe ser un CSV.', 'error')
            return redirect(url_for('opciones.cargar_planilla'))
        
        try:
            # Leer el contenido del CSV
            contenido = archivo.read().decode('utf-8')
            csv_reader = csv.reader(StringIO(contenido))
            
            # Extraer cédulas del CSV
            cedulas_nuevas = set()
            for row in csv_reader:
                if row and row[0].strip():  # Verificar que no esté vacía
                    cedula = row[0].strip()
                    cedulas_nuevas.add(cedula)
            
            if not cedulas_nuevas:
                flash('El archivo CSV está vacío o no contiene cédulas válidas.', 'error')
                return redirect(url_for('opciones.cargar_planilla'))
            
            # Obtener cédulas actuales en la base de datos
            cedulas_actuales = set()
            for doc in collection_planilla.find({}, {"cedula": 1}):
                cedulas_actuales.add(doc["cedula"])
            
            # Calcular diferencias
            cedulas_agregar = cedulas_nuevas - cedulas_actuales
            cedulas_eliminar = cedulas_actuales - cedulas_nuevas
            
            timestamp = datetime.now()
            
            # Agregar nuevas cédulas
            if cedulas_agregar:
                documentos_agregar = []
                for cedula in cedulas_agregar:
                    documentos_agregar.append({
                        "cedula": cedula,
                        "timestamp": timestamp,
                        "accion": "agregado",
                        "usuario": current_user.email
                    })
                collection_planilla.insert_many(documentos_agregar)
            
            # Eliminar cédulas que ya no están en el CSV
            if cedulas_eliminar:
                collection_planilla.delete_many({"cedula": {"$in": list(cedulas_eliminar)}})
            
            # Limpiar el cache de funcionarios CSS para forzar recarga
            import app
            app._funcionarios_cache = None
            
            # Mensaje de éxito
            mensaje = f"Planilla actualizada exitosamente. "
            if cedulas_agregar:
                mensaje += f"Agregadas: {len(cedulas_agregar)} cédulas. "
            if cedulas_eliminar:
                mensaje += f"Eliminadas: {len(cedulas_eliminar)} cédulas. "
            if not cedulas_agregar and not cedulas_eliminar:
                mensaje += "No hubo cambios (la planilla ya estaba actualizada)."
            
            flash(mensaje, 'success')
            
        except Exception as e:
            flash(f'Error al procesar el archivo: {str(e)}', 'error')
        
        return redirect(url_for('opciones.cargar_planilla'))
    
    # GET request - mostrar formulario
    total_funcionarios = collection_planilla.count_documents({})
    ultima_actualizacion = collection_planilla.find_one({}, sort=[("timestamp", -1)])
    
    return render_template('cargar_planilla.html',
                         total_funcionarios=total_funcionarios,
                         ultima_actualizacion=ultima_actualizacion)


@opciones_bp.route('/tablero/opciones/exportar-planilla')
@login_required
def exportar_planilla():
    """Exportar la planilla actual como CSV"""
    def generar_csv():
        yield "cedula\n"  # Header
        for doc in collection_planilla.find({}, {"cedula": 1}).sort("cedula", 1):
            yield f"{doc['cedula']}\n"
    
    return Response(
        generar_csv(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=planilla_funcionarios.csv'}
    )


@opciones_bp.route('/tablero/roles-permisos')
@opciones_bp.route('/tablero/roles-permisos/page/<int:page>')
@login_required
def roles_permisos(page=1):
    # Verificar si el usuario es administrador
    if current_user.rol != 'administrador':
        flash('No tienes permiso para acceder a esta página.', 'error')
        return redirect(url_for('home'))
    
    # Importar colección de usuarios
    from app import collection_usuarios
    
    usuarios_por_pagina = 20
    
    # Definir jerarquía de roles (de mayor a menor)
    jerarquia_roles = {
        'denadoi': 1,
        'coordinador-nacional': 2,
        'coordinador-administrativo': 3,
        'coordinador-regional': 4,
        'subdirector-docencia': 5,
        'coordinador-local': 6,
        'coordinador-departamental': 7,
        'simulacion': 8,  # Agregar simulacion al final
    }
    
    # Obtener todos los usuarios (excluyendo administradores)
    usuarios_cursor = collection_usuarios.find(
        {"rol": {"$ne": "administrador"}}
    )
    
    usuarios = list(usuarios_cursor)
    
    # Asegurar que todos los usuarios tengan el campo permisos
    for usuario in usuarios:
        if 'permisos' not in usuario:
            usuario['permisos'] = []
    
    # Ordenar usuarios por jerarquía de rol, luego por apellidos y nombres
    usuarios.sort(key=lambda u: (
        jerarquia_roles.get(u.get('rol', ''), 999),  # Primero por jerarquía de rol
        u.get('apellidos', '').lower(),               # Luego por apellidos
        u.get('nombres', '').lower()                  # Finalmente por nombres
    ))
    
    # Contar total de usuarios
    total_usuarios = len(usuarios)
    
    # Calcular total de páginas
    total_paginas = (total_usuarios + usuarios_por_pagina - 1) // usuarios_por_pagina
    
    # Aplicar paginación manualmente
    inicio = (page - 1) * usuarios_por_pagina
    fin = inicio + usuarios_por_pagina
    usuarios_pagina = usuarios[inicio:fin]
    
    # Definir permisos disponibles
    permisos_disponibles = [
        {'id': 'lms_admin', 'nombre': 'LMS Admin', 'descripcion': 'Crear y editar contenidos LMS'},
        {'id': 'lms_view', 'nombre': 'LMS Ver', 'descripcion': 'Ver contenidos LMS'},
        {'id': 'qbanks_admin', 'nombre': 'Qbanks Admin', 'descripcion': 'Gestionar bancos de preguntas'},
        {'id': 'metricas_avanzadas', 'nombre': 'Métricas Avanzadas', 'descripcion': 'Ver métricas detalladas'},
        {'id': 'exportar_datos', 'nombre': 'Exportar Datos', 'descripcion': 'Exportar bases de datos'},
        {'id': 'gestionar_usuarios', 'nombre': 'Gestionar Usuarios', 'descripcion': 'Crear y editar usuarios'}
    ]
    
    return render_template('roles_permisos.html',
                         usuarios=usuarios_pagina,
                         permisos_disponibles=permisos_disponibles,
                         page=page,
                         total_paginas=total_paginas,
                         total_usuarios=total_usuarios)


@opciones_bp.route('/tablero/roles-permisos/actualizar/<user_id>', methods=['POST'])
@login_required
def actualizar_permisos(user_id):
    # Verificar si el usuario es administrador
    if current_user.rol != 'administrador':
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('home'))
    
    from app import collection_usuarios
    from bson import ObjectId
    
    # Obtener el usuario
    usuario = collection_usuarios.find_one({"_id": ObjectId(user_id)})
    
    if not usuario:
        flash('Usuario no encontrado.', 'error')
        return redirect(url_for('opciones.roles_permisos'))
    
    # Obtener permisos del formulario
    permisos_nuevos = []
    permisos_posibles = ['lms_admin', 'lms_view', 'qbanks_admin', 'metricas_avanzadas', 'exportar_datos', 'gestionar_usuarios']
    
    for permiso in permisos_posibles:
        if request.form.get(permiso) == 'on':
            permisos_nuevos.append(permiso)
    
    # Actualizar permisos en la base de datos
    collection_usuarios.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"permisos": permisos_nuevos}}
    )
    
    # Log de la acción
    from app import log_event
    log_event(f"Usuario [{current_user.email}] actualizó permisos de {usuario.get('email')}: {permisos_nuevos}")
    
    flash(f'Permisos actualizados para {usuario.get("nombres")} {usuario.get("apellidos")}.', 'success')
    return redirect(url_for('opciones.roles_permisos'))