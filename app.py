from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, session, abort, send_from_directory, Response
from flask_login import LoginManager, login_user, UserMixin, logout_user, current_user, login_required
from pymongo import MongoClient
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime, timedelta
from PIL import Image
from markupsafe import Markup
from config import config
import os
import random
import string
import hashlib
import base64
from io import BytesIO, StringIO
import csv

app = Flask(__name__)


###
### Configuraciones comunes
###
app.config.from_object(config)                              # Cargar configuraciones desde config.py

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # Configura ProxyFix para forzar https cuando se esta detrás de un proxy inverso

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)     # Crear la carpeta de subida si no existe

client = MongoClient(app.config['MONGO_URI'])               # Configurar MongoDB usando la URI de la configuración
db = client['certi_css']
collection_eventos = db['eventos']
collection_participantes = db['participantes']
collection_usuarios = db['usuarios']
collection_preregistro = db['preregistro']
collection_eva = db['eva']
collection_tokens = db['tokens']
collection_repositorio = db['repositorio']
collection_encuestas = db['encuestas'] 
collection_qbanks = db['qbanks']
collection_qbanks_data = db['qbanks_data']
collection_exam_results = db['exam_results']


###
### Variables globales personalizadas
###
@app.context_processor                                      # Variable BASE_URL
def inject_base_url():
    return dict(BASE_URL=app.config['BASE_URL'])

app.jinja_env.globals['now'] = datetime.now                 # Variable now para fecha actual

def load_version():                                         # Cargar la versión una sola vez al iniciar la aplicación
    try:
        with open("version.txt", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "Unknown"

VERSION = load_version()                                    # Variable global con la versión

@app.context_processor
def inject_version():
    return dict(version=VERSION)

@app.context_processor                                      # Variable global UMAMI
def inject_umami():
    return dict(UMAMI_URL=app.config.get('UMAMI_URL', ''))


###
### Login
###
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    user_data = collection_usuarios.find_one({"_id": ObjectId(user_id)})
    if user_data:
        user = User(
            email=user_data['email'],
            password=user_data['password'],
            rol=user_data['rol'],
            cedula=user_data.get('cedula', ''),
            nombres=user_data.get('nombres', ''),
            apellidos=user_data.get('apellidos', ''),
            foto=user_data.get('foto')
        )
        user.id = str(user_data['_id'])
        return user
    return None


class User(UserMixin):
    def __init__(self, email, password, rol, nombres, apellidos, cedula, foto=None):
        self.email = email
        self.password = password
        self.rol = rol
        self.nombres = nombres
        self.apellidos = apellidos
        self.cedula = cedula
        self.foto = foto
        self.id = None

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)


###
### Crear índice único para evitar duplicados
###
try:
    # Eliminar índices existentes
    collection_participantes.drop_indexes()
    # Crear el nuevo índice
    collection_participantes.create_index([("cedula", 1), ("codigo_evento", 1), ("titulo_ponencia", 1), ("indice_registro", 1)], unique=True)
except Exception as e:
    print(f"Error al crear índice: {e}")


###
### Función código OTP
###
otp_storage = {}

def generate_otp():
    """Genera un código OTP de 4 dígitos (mayúsculas y números)."""
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for _ in range(4))


###
### OTP dinámico
###
@app.route('/get-otp/<codigo_evento>')
def get_otp(codigo_evento):
    # Verificar si el OTP existe y no ha expirado
    if codigo_evento in otp_storage and datetime.now() < otp_storage[codigo_evento]['valid_until']:
        otp_code = otp_storage[codigo_evento]['code']
    else:
        # Generar un nuevo OTP
        otp_code = generate_otp()
        otp_storage[codigo_evento] = {
            'code': otp_code,
            'valid_until': datetime.now() + timedelta(seconds=90)
        }

    # Devolver el OTP en formato JSON
    return jsonify(otp=otp_code)


###
### Función código nanoid
###
def generate_nanoid(cedula, codigo_evento, titulo_ponencia=None):
    """Genera un hash nanoid truncado a 8 caracteres utilizando cédula, código de evento y opcionalmente título de ponencia."""
    # Si no se proporciona un título de ponencia, usar una cadena vacía
    if titulo_ponencia is None:
        titulo_ponencia = ""
    base_string = f"{cedula}{codigo_evento}{titulo_ponencia}"
    hash_object = hashlib.sha256(base_string.encode())
    return hash_object.hexdigest()[:8]


###
### Función que genera código evento
###
def generar_codigo_evento(longitud=6):
    caracteres = string.ascii_uppercase + string.digits
    codigo = ''.join(random.choice(caracteres) for _ in range(longitud))
    return codigo

def obtener_codigo_unico():
    while True:
        codigo = generar_codigo_evento()
        if collection_eventos.find_one({"codigo": codigo}) is None:
            return codigo


###
### Página de registro
###
@app.route('/tablero/usuarios/registrar', methods=['GET', 'POST'])
@login_required
def registro():
    if request.method == 'POST':
        nombres = request.form['nombres']
        apellidos = request.form['apellidos']
        genero = request.form['genero']
        cedula = request.form['cedula']
        orcid = request.form['orcid']
        email = request.form['email']
        password = request.form['password']
        rol = request.form['rol']
        cargo = request.form['cargo']
        region = request.form['region']
        unidad_ejecutora = request.form['unidad_ejecutora']
        departamento = request.form['departamento']
        phone = request.form['phone']
        timestamp = datetime.now()

        # Verificar si el usuario ya existe
        if collection_usuarios.find_one({"email": email}):
            flash('El usuario ya existe.')
            return redirect(url_for('registro'))

        # Crear un nuevo usuario y guardar en la base de datos
        hashed_password = generate_password_hash(password)
        collection_usuarios.insert_one({
            'nombres': nombres,
            'apellidos': apellidos,
            'genero': genero,
            'cedula': cedula,
            'email': email,
            'orcid': orcid,
            'phone': phone,
            'password': hashed_password,
            'rol': rol,
            'cargo': cargo,
            'region': region,
            'unidad_ejecutora': unidad_ejecutora,
            'departamento': departamento,
            'jefe': False,
            'subjefe': False,
            'activo': True,
            'timestamp': timestamp
        })
        log_event(f"Usuario [{current_user.email}] registró un nuevo usuario: {email}.")
        return redirect(url_for('listar_usuarios'))

    return render_template('registrar_usuario.html')


###
### Login
###
@app.route('/iniciar_sesion', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user_data = collection_usuarios.find_one({"email": email})

        if user_data:
            # Verificar si el usuario está bloqueado
            if user_data.get('blocked_until') and user_data['blocked_until'] > datetime.utcnow():
                log_event(f"Usuario [{email}] intentó ingresar con la cuenta bloqueada temporalmente.")
                flash('Esta cuenta está bloqueada temporalmente. Intente más tarde.', 'error')
                return render_template('iniciar_sesion.html')

            # Verificar si el usuario está activo
            if not user_data.get('activo', False):  # Si 'activo' es False o no existe
                log_event(f"Usuario [{email}] intentó ingresar con una cuenta inactiva.")
                flash('Esta cuenta está inactiva. Contacte al administrador.', 'error')
                return render_template('iniciar_sesion.html')

            # Verificar la contraseña
            if check_password_hash(user_data['password'], password):
                # Reiniciar intentos fallidos si el inicio de sesión es exitoso
                collection_usuarios.update_one(
                    {"email": email},
                    {"$set": {"failed_attempts": 0, "last_failed_attempt": None, "blocked_until": None}}
                )
                user = User(
                    email=user_data['email'],
                    password=user_data['password'],
                    rol=user_data['rol'],
                    cedula=user_data.get('cedula', ''),
                    nombres=user_data.get('nombres', ''),
                    apellidos=user_data.get('apellidos', '')
                )
                user.id = str(user_data['_id'])
                login_user(user)
                session.permanent = True
                log_event(f"Usuario [{email}] ingresó exitosamente.")
                return redirect(url_for('tablero_coordinadores'))
            else:
                # Incrementar intentos fallidos
                failed_attempts = user_data.get('failed_attempts', 0) + 1
                last_failed_attempt = datetime.utcnow()

                # Bloquear después de 5 intentos fallidos
                if failed_attempts >= 5:
                    blocked_until = last_failed_attempt + timedelta(minutes=15)
                    collection_usuarios.update_one(
                        {"email": email},
                        {"$set": {"failed_attempts": failed_attempts, "last_failed_attempt": last_failed_attempt, "blocked_until": blocked_until}}
                    )
                    log_event(f"Usuario [{email}] ha bloqueado la cuenta.")
                    flash('Has excedido el número máximo de intentos. La cuenta ha sido bloqueada por 15 minutos.', 'error')
                else:
                    collection_usuarios.update_one(
                        {"email": email},
                        {"$set": {"failed_attempts": failed_attempts, "last_failed_attempt": last_failed_attempt}}
                    )
                    log_event(f"Usuario [{email}] intentó ingresar con credenciales incorrectas.")
                    flash('Credenciales incorrectas. Inténtalo de nuevo.', 'error')

        else:
            log_event(f"Usuario [{email}] intentó ingresar con credenciales incorrectas.")
            flash('Credenciales incorrectas. Inténtalo de nuevo.', 'error')

    return render_template('iniciar_sesion.html')


###
### Listado de usuarios
###
@app.route('/tablero/usuarios')
@app.route('/tablero/usuarios/page/<int:page>')
@login_required
def listar_usuarios(page=1):
    usuarios_por_pagina = 20  # Número de usuarios por página

    # Contar el total de usuarios
    total_usuarios = collection_usuarios.count_documents({"rol": {"$ne": "administrador"}})  # Excluir administradores si es necesario
    # Calcular el número total de páginas
    total_paginas = (total_usuarios + usuarios_por_pagina - 1) // usuarios_por_pagina  # Redondear hacia arriba

    # Obtener los usuarios para la página actual
    usuarios_cursor = collection_usuarios.find({"rol": {"$ne": "administrador"}}).sort([("apellidos", 1), ("nombres", 1)]).skip((page - 1) * usuarios_por_pagina).limit(usuarios_por_pagina)
    usuarios = list(usuarios_cursor)

    for usuario in usuarios:
        usuario['foto_url'] = f"/static/usuarios/{usuario['foto']}" if usuario.get('foto') else "/static/assets/user-avatar.png"

    return render_template('usuarios.html',
        usuarios=usuarios,
        page=page,
        total_paginas=total_paginas,
        total_usuarios=total_usuarios
    )


###
### Edición de perfil de usuario
###
@app.route('/tablero/usuarios/<user_id>/editar', methods=['GET', 'POST'])
@login_required
def editar_usuario(user_id):
    if request.method == 'POST':
        usuario = collection_usuarios.find_one({"_id": ObjectId(user_id)})
        if not usuario:
            return redirect(url_for('listar_usuarios'))

        # Recoger los datos del formulario
        nombres = request.form.get('nombres')
        apellidos = request.form.get('apellidos')
        genero = request.form.get('genero')
        cedula = request.form.get('cedula')
        orcid = request.form.get('orcid')
        rol = request.form.get('rol')
        cargo = request.form.get('cargo')
        region = request.form.get('region')
        unidad_ejecutora = request.form.get('unidad_ejecutora')
        departamento = request.form.get('departamento')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')

        jefe = request.form.get('jefe') == 'on' if 'jefe' in request.form else usuario.get('jefe', False)
        subjefe = request.form.get('subjefe') == 'on' if 'subjefe' in request.form else usuario.get('subjefe', False)

        # Crear un diccionario con los nuevos datos
        updated_user_data = {
            "nombres": nombres,
            "apellidos": apellidos,
            "genero": genero,
            "cedula": cedula,
            "orcid": orcid,
            "region": region,
            "phone": phone,
            "unidad_ejecutora": unidad_ejecutora,
            "departamento": departamento,
            "rol": rol,
            "cargo": cargo,
            "jefe": jefe,
            "subjefe": subjefe,
        }

        # Procesar la foto de perfil
        foto_file = request.files.get('foto')
        if foto_file and allowed_file(foto_file.filename):
            foto_filename = f"{user_id}-foto.jpg"
            foto_path = os.path.join(app.config['USERS_FOLDER'], foto_filename)

            image = Image.open(foto_file)
            if image.mode != 'RGB':
                image = image.convert('RGB')

            # Redimensionar y recortar la imagen a 750x750 píxeles
            width, height = image.size

            # Calcular el tamaño del recorte
            if width > height:
                # La imagen es más ancha que alta
                left = (width - height) / 2
                top = 0
                right = (width + height) / 2
                bottom = height
            else:
                # La imagen es más alta que ancha
                left = 0
                top = (height - width) / 2
                right = width
                bottom = (height + width) / 2

            # Recortar la imagen
            image_cropped = image.crop((left, top, right, bottom))
            image_resized = image_cropped.resize((450, 450), Image.Resampling.LANCZOS)

            # Guardar la imagen
            image_resized.save(foto_path, 'JPEG')
            updated_user_data["foto"] = foto_filename

        # Solo actualizar la contraseña si se proporciona
        if password:
            updated_user_data["password"] = generate_password_hash(password)  # Asegúrate de importar y usar esta función

        # Actualizar el usuario en la base de datos
        collection_usuarios.update_one({"_id": ObjectId(user_id)}, {"$set": updated_user_data})

        email = usuario.get('email')

        if current_user.email == email:
            log_event(f"Usuario [{current_user.email}] actualizó su perfil.")
        else:
            log_event(f"Usuario [{current_user.email}] actualizó el perfil de usuario de {email}.")
        return redirect(url_for('listar_usuarios'))  # Redirigir a la lista de usuarios

    # Obtener los datos del usuario
    usuario = collection_usuarios.find_one({"_id": ObjectId(user_id)})

    if usuario.get('foto'):
        foto_url = f"/static/usuarios/{usuario['foto']}"
    else:
        foto_url = None

    return render_template('editar_usuario.html', usuario=usuario, foto_url=foto_url)


def allowed_file(filename):
    """Verifica si la extensión del archivo está permitida."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


###
### Eliminar foto de perfil
###
@app.route('/tablero/usuarios/<user_id>/eliminar_foto', methods=['POST'])
@login_required
def eliminar_foto(user_id):
    print(f"Intentando eliminar la foto del usuario: {user_id}")  # Debug

    usuario = collection_usuarios.find_one({"_id": ObjectId(user_id)})

    if not usuario or not usuario.get("foto"):
        print("No se encontró una foto asociada en la base de datos.")  # Debug
        return redirect(url_for('editar_usuario', user_id=user_id))

    # Ruta de la foto en el servidor
    foto_path = os.path.join(app.config['USERS_FOLDER'], f"{user_id}-foto.jpg")
    print(f"Ruta de la foto: {foto_path}")  # Debug
    print(f"Existe en el servidor: {os.path.exists(foto_path)}")  # Debug

    # Intentar eliminar la foto
    try:
        if os.path.exists(foto_path):
            os.remove(foto_path)
            print("Foto eliminada correctamente.")  # Debug
        else:
            print("Foto no encontrada en el servidor.")  # Debug
    except Exception as e:
        print(f"Error al eliminar la foto: {str(e)}")  # Debug

    # Actualizar la base de datos
    collection_usuarios.update_one({"_id": ObjectId(user_id)}, {"$unset": {"foto": 1}})
    print("Registro de la foto eliminado de la base de datos.")  # Debug

    log_event(f"Usuario [{current_user.email}] eliminó la foto de perfil de {usuario.get('email')}.")

    return redirect(url_for('editar_usuario', user_id=user_id))


###
### Perfil de usuario
###
@app.route('/tablero/usuarios/<user_id>')
@login_required
def mostrar_usuario(user_id):
    # Obtener los datos del usuario desde la base de datos usando el user_id
    usuario = collection_usuarios.find_one({"_id": ObjectId(user_id)})

    foto_url = f"/static/usuarios/{usuario['foto']}" if usuario.get('foto') else None

    if not usuario:
        flash("Usuario no encontrado", "danger")
        return redirect(url_for('listar_usuarios'))  # Redirigir a la lista de usuarios si no se encuentra

    return render_template('perfil_usuario.html', usuario=usuario, foto_url=foto_url)


###
### Acciones de usuario
###
@app.route('/tablero/usuarios/<user_id>/eliminar', methods=['POST'])
@login_required
def eliminar_usuario(user_id):
    if current_user.rol != 'administrador':
        flash('No tienes permisos para realizar esta acción.', 'error')
        return redirect(url_for('listar_usuarios'))

    # Obtener el usuario que se va a eliminar
    usuario = collection_usuarios.find_one({"_id": ObjectId(user_id)})

    if not usuario:
        flash('Usuario no encontrado.', 'error')
        return redirect(url_for('listar_usuarios'))

    # Obtener el email del usuario que se va a eliminar
    email = usuario.get('email')

    # Eliminar el usuario de la base de datos
    collection_usuarios.delete_one({"_id": ObjectId(user_id)})

    log_event(f"Usuario [{current_user.email}] eliminó el usuario {email}.")
    flash('Usuario eliminado con éxito.')
    return redirect(url_for('listar_usuarios'))


@app.route('/tablero/usuarios/<user_id>/toggle_activo', methods=['POST'])
@login_required
def toggle_activo(user_id):
    if current_user.rol != 'administrador':
        flash('No tienes permisos para realizar esta acción.', 'error')
        return redirect(url_for('listar_usuarios'))

    usuario = collection_usuarios.find_one({"_id": ObjectId(user_id)})
    if not usuario:
        flash('Usuario no encontrado.', 'error')
        return redirect(url_for('listar_usuarios'))

    email = usuario.get('email')

    # Cambiar el estado de "activo"
    nuevo_estado = not usuario.get('activo', False)
    collection_usuarios.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"activo": nuevo_estado}}
    )

    log_event(f"Usuario [{current_user.email}] cambió el estado de {email} a {'activo' if nuevo_estado else 'inactivo'}.")
    return redirect(url_for('listar_usuarios'))


###
###
###
@app.route('/editar_participante/<nanoid>', methods=['GET', 'POST'])
def editar_participante(nanoid):

    participante = collection_participantes.find_one({"nanoid": nanoid})

    if not participante:
        abort(404)  # Si no se encuentra el participante, devuelve un error 404

    codigo_evento = participante['codigo_evento']
    evento = collection_eventos.find_one({"codigo": codigo_evento})

    if request.method == 'POST':
        # Obtener los datos del formulario
        nombres = request.form.get('nombres')
        apellidos = request.form.get('apellidos')
        cedula = request.form.get('cedula')
        perfil = request.form.get('perfil_profesional')
        region = request.form.get('region')
        unidad = request.form.get('unidad')

        # Actualizar el participante en la base de datos
        collection_participantes.update_one(
            {"nanoid": nanoid},
            {"$set": {
                "nombres": nombres,
                "apellidos": apellidos,
                "cedula": cedula,
                "perfil": perfil,
                'region': region,
                'unidad': unidad,
            }}
        )

        return redirect(url_for('listar_participantes', codigo_evento=participante['codigo_evento']))

    return render_template('editar_participante.html', participante=participante, evento=evento)


###
###
###
@app.route('/editar_ponente/<nanoid>', methods=['GET', 'POST'])
def editar_ponente(nanoid):

    ponente = collection_participantes.find_one({"nanoid": nanoid})

    if not ponente:
        abort(404)  # Si no se encuentra el participante, devuelve un error 404

    codigo_evento = ponente['codigo_evento']
    evento = collection_eventos.find_one({"codigo": codigo_evento})

    if request.method == 'POST':
        # Obtener los datos del formulario
        nombres = request.form.get('nombres', '').strip()
        apellidos = request.form.get('apellidos', '').strip()
        cedula = request.form.get('cedula', '').strip()
        perfil = request.form.get('perfil_profesional').strip()
        titulo_ponencia = request.form.get('titulo_ponencia', '').strip()

        # Actualizar el participante en la base de datos
        collection_participantes.update_one(
            {"nanoid": nanoid},
            {"$set": {
                "nombres": nombres,
                "apellidos": apellidos,
                "cedula": cedula,
                "perfil": perfil,
                "titulo_ponencia": titulo_ponencia,
            }}
        )

        return redirect(url_for('listar_participantes', codigo_evento=ponente['codigo_evento']))

    return render_template('editar_ponente.html', ponente=ponente, evento=evento)


###
###
###
@app.route('/salir', methods=['POST'])
def salir():
    logout_user()
    return redirect(url_for('home'))


###
### Home
###
@app.route('/')
def home():
    inicio_hoy = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    eventos_futuros = collection_eventos.find({
        "fecha_inicio": {"$gte": inicio_hoy},
        "estado_evento": {"$ne": "borrador"}
    }).sort("fecha_inicio").limit(3)

    return render_template('home.html', eventos=eventos_futuros)


###
### Catálogo eventos
###
@app.route('/catalogo/<int:page>', methods=['GET'])
def catalogo(page=1):
    per_page = 15  # Número máximo de eventos por página
    skip = (page - 1) * per_page

    # Contar total de eventos
    total_eventos = collection_eventos.count_documents({})  # Contar el total de eventos
    total_pages = (total_eventos + per_page - 1) // per_page  # Calcular el total de páginas

    # Verificar si la página solicitada es válida
    if page < 1 or page > total_pages:
        abort(404)  # Forzar un error 404 si la página no existe

    # Obtener eventos paginados
    eventos = collection_eventos.find(
        {"estado_evento": {"$ne": "borrador"}}
    ).sort("fecha_inicio", -1).skip(skip).limit(per_page)

    return render_template('catalogo.html', eventos=eventos, page=page, total_pages=total_pages)


###
### Dashboard
###
@app.route('/tablero')
@login_required
def tablero_coordinadores():

    ## Tarjetas

    # Obtener el número total de usuarios
    total_usuarios = collection_usuarios.count_documents({"rol": {"$ne": "administrador"}})
    # Obtener el número total de eventos
    total_eventos = collection_eventos.count_documents({})
    # Contar el número total de ponentes
    total_ponentes = collection_participantes.count_documents({"rol": "ponente"})
    # Contar el número total de participantes
    total_participantes = collection_participantes.count_documents({"rol": "participante"})

    ## Resumen Eventos

    # Consulta de eventos próximos y en curso si hay alguno en la consulta
    ahora = datetime.utcnow()
    # Normaliza al inicio del día actual
    inicio_hoy = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    # Consulta a MongoDB para incluir desde el inicio del día actual en adelante
    eventos_prox = collection_eventos.find({ 'fecha_inicio': {'$gte': inicio_hoy} }).sort('fecha_inicio').limit(5)
    eventos_prox_list = list(eventos_prox)

    #Etiqueta de estado
    eventos_prox_list_estado = []
    for evento in eventos_prox_list:
        fecha_inicio = evento['fecha_inicio']
        if fecha_inicio.date() == ahora.date():
            evento['estado'] = 'En curso'
        elif fecha_inicio.date() < ahora.date():
            evento['estado'] = 'Finalizado'
        else:
            evento['estado'] = 'Publicado'

        # Verificar si el usuario es organizador o coorganizador en cada evento
        es_organizador = collection_participantes.find_one({
            "codigo_evento": evento["codigo"],
            "cedula": str(current_user.cedula),
            "rol": "coorganizador",
        }) is not None 

        evento["es_organizador"] = es_organizador
        
        # Para depuración
        print(f"Evento {evento['codigo']}, es_organizador: {es_organizador}")
        
        eventos_prox_list_estado.append(evento)  # CORREGIDO: añadir el evento solo una vez

    num_eventos = len(eventos_prox_list)

    usuarios_recientes = list(collection_usuarios.find({"rol": {"$ne": "administrador"}}).sort("fecha_registro", 1).limit(5))

    num_usuarios_recientes = len(usuarios_recientes)

    for usuario in usuarios_recientes:
        usuario['foto_url'] = f"/static/usuarios/{usuario['foto']}" if usuario.get('foto') else "/static/assets/user-avatar.png"

    return render_template('tablero.html',
        eventos=eventos_prox_list,
        eventos_estado=eventos_prox_list_estado,
        ahora=ahora,
        num_eventos=num_eventos,
        usuarios=usuarios_recientes,
        num_usuarios=num_usuarios_recientes,
        active_section='tablero',
        total_usuarios=total_usuarios,
        total_eventos=total_eventos,
        total_ponentes=total_ponentes,
        total_participantes=total_participantes,
    )


###
### Formulario de registro de participantes
###
@app.route('/registrar_participante/<codigo_evento>')
def registrar_participante(codigo_evento):
    # Verificar si el código del evento existe en la base de datos
    evento = collection_eventos.find_one({"codigo": codigo_evento})

    if evento is None:
        abort(404)

    es_presencial = evento.get("modalidad", "") == "Presencial"

    # Verificar si el evento está cerrado
    if evento.get('estado_evento') == 'cerrado':
        return render_template('registrar.html',
            evento_cerrado=True,
            nombre_evento=evento['nombre'],
            afiche_url=url_for('static', filename='uploads/' + evento['afiche_750'].split('/')[-1])
        )

    # Plantilla diferente según el tipo de evento
    if es_presencial:
        # Eventos presenciales
        if codigo_evento not in otp_storage or datetime.now() >= otp_storage[codigo_evento]['valid_until']:
            otp_code = generate_otp()
            otp_storage[codigo_evento] = {
                'code': otp_code,
                'valid_until': datetime.now() + timedelta(minutes=1)
            }
        else:
            otp_code = otp_storage[codigo_evento]['code']

        return render_template('registrar_presencial.html',
            otp=otp_code,
            evento=evento,
            codigo_evento=codigo_evento,
            nombre_evento=evento['nombre'],
            afiche_url=evento.get('afiche_750') if evento.get('afiche_750') else None,
            programa_url=evento.get('programa_url')
        )
    else:
        # Eventos no presenciales
        return render_template('registrar_virtual.html',
            evento=evento,
            codigo_evento=codigo_evento,
            nombre_evento=evento['nombre'],
            afiche_url=evento.get('afiche_750') if evento.get('afiche_750') else None,
            programa_url=evento.get('programa_url')
        )


@app.route('/registrar', methods=['POST'])
def registrar():
    nombres = request.form['nombres']
    apellidos = request.form['apellidos']
    cedula = request.form['cedula']
    rol = request.form['rol']
    perfil = request.form['perfil_profesional']
    region = request.form['region']
    unidad = request.form['unidad']
    codigo_evento = request.form['codigo_evento']
    #otp_ingresado = request.form['otp']
    timestamp = datetime.now()

    # Obtener el evento
    evento = collection_eventos.find_one({"codigo": codigo_evento})

    if evento is None:
        flash("El código del evento no es válido.", "error")
        return redirect(url_for('registrar_participante', codigo_evento=codigo_evento))

    es_presencial = evento.get("modalidad", "") == "Presencial"

    # Verificar si el participante ya está registrado en este evento
    if collection_participantes.find_one({"cedula": cedula, "codigo_evento": codigo_evento, "rol": "participante", "indice_registro": datetime.now().strftime('%Y%m%d')}):
        flash("El participante ya está registrado en este evento.", "error")
        return redirect(url_for('registrar_participante', codigo_evento=codigo_evento))

    # Proceso según tipo de evento
    if es_presencial:
        # Eventos presenciales, validamos OTP
        otp_ingresado = request.form.get('otp', '')

        # Verificar si el código OTP existe y su validez
        if codigo_evento in otp_storage:
            otp_info = otp_storage[codigo_evento]

            # Validar si el registro se realizó durante la validez del OTP y si coincide con el OTP ingresado
            if datetime.now() > otp_info['valid_until'] or otp_ingresado != otp_info['code']:
                flash("El OTP ha expirado o es incorrecto.", "error")
                return redirect(url_for('registrar_participante', codigo_evento=codigo_evento))
        else:
            flash("El código del evento no es válido.", "error")
            return redirect(url_for('registrar_participante', codigo_evento=codigo_evento))
    else:
        # Para eventos no presenciales, validamos contra preregistro
        preregistro = collection_preregistro.find_one({"codigo_evento": codigo_evento, "cedula": cedula})
        if preregistro is None:
            flash("Su cédula no está preregistrada para este evento virtual.", "error")
            return redirect(url_for('registrar_participante', codigo_evento=codigo_evento))

    # Si llegamos aquí, todas las validaciones han pasado :)
    # Generar nanoid
    nanoid = generate_nanoid(cedula, codigo_evento)

    # Insertar datos en la colección de MongoDB
    collection_participantes.insert_one({
        'nombres': nombres,
        'apellidos': apellidos,
        'cedula': cedula,
        'rol': rol,
        'perfil': perfil,
        'region': region,
        'unidad': unidad,
        'codigo_evento': codigo_evento,
        'nanoid': nanoid,
        'timestamp': timestamp,
        'indice_registro': datetime.now().strftime('%Y%m%d'),
        'tipo_evento': 'Presencial' if es_presencial else 'Virtual'
    })

    # Mensaje de éxito
    flash("Registro exitoso. El certificado de participación se podrá descargar al finalizar el evento.", "success")
    return redirect(url_for('registrar_participante', codigo_evento=codigo_evento))


###
### Redirección corta (solo registro de evento)
###
@app.route('/<codigo_evento>')
def redirigir_ruta_corta(codigo_evento):
    return redirect(url_for('registrar_participante', codigo_evento=codigo_evento))


###
### Formulario de preregistro
###
@app.route('/preregistro/<codigo_evento>', methods=['GET', 'POST'])
@login_required
def preregistro(codigo_evento):
    # Obtener cédulas existentes de la colección preregistros
    cedulas_guardadas = [registro["cedula"] for registro in collection_preregistro.find({"codigo_evento": codigo_evento}, {"cedula": 1, "_id": 0})]

    evento = collection_eventos.find_one({"codigo": codigo_evento})
    nombre_evento = evento['nombre'] if evento else "Evento no encontrado"
    fecha_inicio = evento.get('fecha_inicio') if evento else None


    if request.method == "POST":
        datos_formulario = request.form.get("cedulas", "")

        # Dividir el contenido usando la línea de guiones como separador
        partes = datos_formulario.split("-----")

        if len(partes) >= 2:
            # La primera parte contiene las cédulas existentes (posiblemente modificadas)
            cedulas_existentes_actualizadas = {c.strip() for c in partes[0].split("\n") if c.strip()}

            # Nuevas cédulas están después del separador
            nuevas_cedulas = {c.strip() for c in partes[1].split("\n") if c.strip()}

            # Identificar cédulas que fueron eliminadas
            cedulas_a_eliminar = set(cedulas_guardadas) - cedulas_existentes_actualizadas
            if cedulas_a_eliminar:
                for cedula in cedulas_a_eliminar:
                    collection_preregistro.delete_one({"codigo_evento": codigo_evento, "cedula": cedula})
                flash(f"Se han eliminado {len(cedulas_a_eliminar)} cédulas del registro.", "danger")

            # Insertar nuevas cédulas
            cedulas_a_insertar = [c for c in nuevas_cedulas if c not in cedulas_existentes_actualizadas]
            if cedulas_a_insertar:
                documentos = [{"codigo_evento": codigo_evento, "cedula": c} for c in cedulas_a_insertar]
                collection_preregistro.insert_many(documentos)
                flash(f"Se han preregistrado {len(cedulas_a_insertar)} nuevas cédulas.", "success")

        else:
            # Si no hay separador, consideramos todo como nuevas cédulas
            nuevas_cedulas = {c.strip() for c in datos_formulario.split("\n") if c.strip()}
            cedulas_a_insertar = [c for c in nuevas_cedulas if c not in cedulas_guardadas]

            if cedulas_a_insertar:
                documentos = [{"codigo_evento": codigo_evento, "cedula": c} for c in cedulas_a_insertar]
                collection_preregistro.insert_many(documentos)
                flash(f"Se han preregistrado {len(cedulas_a_insertar)} nuevas cédulas.", "success")
            else:
                flash("Todas las cédulas ingresadas ya están registradas.", "info")

        # Redireccionar para actualizar la lista
        return redirect(url_for('preregistro', codigo_evento=codigo_evento))

    # Actualizar la lista de cédulas guardadas después de posibles cambios
    cedulas_guardadas = [registro["cedula"] for registro in collection_preregistro.find({"codigo_evento": codigo_evento}, {"cedula": 1, "_id": 0})]

    cupos = evento.get('cupos') if evento else None
    total_registrados = collection_participantes.count_documents({"codigo_evento": codigo_evento, "rol": "participante"})
    total_preregistrados = len(cedulas_guardadas)

    return render_template('preregistro.html',
                           codigo_evento=codigo_evento,
                           nombre_evento=nombre_evento,
                           fecha_inicio=fecha_inicio,
                           cedulas_guardadas=cedulas_guardadas,
                           total_preregistrados=total_preregistrados,
                           cupos=cupos,
                           total_registrados=total_registrados)


###
### Formulario de registro de ponentes
###
@app.route('/registrar_ponente/<codigo_evento>', methods=['GET', 'POST'])
@login_required
def registrar_ponente(codigo_evento):
    evento = collection_eventos.find_one({"codigo": codigo_evento})

    afiche_750 = evento.get('afiche_750')
    afiche_url = url_for('static', filename='uploads/' + afiche_750.split('/')[-1]) if afiche_750 else None

    # Verificar si el evento está cerrado
    if evento.get('estado_evento') == 'cerrado':
        return render_template('registrar_ponente.html',
            evento_cerrado=True,
            nombre_evento=evento['nombre'],
            afiche_url=afiche_url
        )

    if request.method == 'POST':
        nombres = request.form['nombres']
        apellidos = request.form['apellidos']
        cedula = request.form['cedula']
        perfil = request.form['perfil_profesional']
        rol = request.form['rol']
        titulo_ponencia = request.form['titulo_ponencia']

        # Generar nanoid
        nanoid = generate_nanoid(cedula, codigo_evento, titulo_ponencia)

        # Insertar datos en la colección de MongoDB
        collection_participantes.insert_one({
            'nombres': nombres,
            'apellidos': apellidos,
            'cedula': cedula,
            'perfil': perfil,
            'rol': rol,
            'titulo_ponencia': titulo_ponencia,
            'codigo_evento': codigo_evento,
            'nanoid': nanoid,
            'indice_registro': datetime.now().strftime('%Y%m%d'),
            'timestamp': datetime.now()  # Almacenar timestamp actual
        })

        flash("Ponente registrado con éxito.", "success")
        log_event(f"Usuario [{current_user.email}] registró al {rol} {cedula} en el evento {codigo_evento}.")
        return redirect(url_for('listar_participantes', codigo_evento=codigo_evento))

    return render_template('registrar_ponente.html',
        codigo_evento=codigo_evento,
        evento=evento,
        afiche_url=afiche_url
    )


###
### Formulario de registro de organizadores
###
@app.route('/registrar_organizador/<codigo_evento>', methods=['GET', 'POST'])
@login_required
def registrar_organizador(codigo_evento):
    evento = collection_eventos.find_one({"codigo": codigo_evento})

    afiche_750 = evento.get('afiche_750')
    afiche_url = url_for('static', filename='uploads/' + afiche_750.split('/')[-1]) if afiche_750 else None

    # Verificar si el evento está cerrado
    if evento.get('estado_evento') == 'cerrado':
        return render_template('registrar_organizador.html',
            evento_cerrado=True,
            nombre_evento=evento['nombre'],
            afiche_url=afiche_url
        )

    if request.method == 'POST':
        nombres = request.form['nombres']
        apellidos = request.form['apellidos']
        cedula = request.form['cedula']
        rol = request.form['rol']
        
        titulo_ponencia = rol                # hack para poder registrar

        # Generar nanoid
        nanoid = generate_nanoid(cedula, codigo_evento, titulo_ponencia)

        # Insertar datos en la colección de MongoDB
        collection_participantes.insert_one({
            'nombres': nombres,
            'apellidos': apellidos,
            'cedula': cedula,
            'rol': rol,
            'codigo_evento': codigo_evento,
            'nanoid': nanoid,
            'titulo_ponencia': titulo_ponencia,
            'indice_registro': datetime.now().strftime('%Y%m%d'),
            'timestamp': datetime.now()     # Almacenar timestamp actual
        })

        flash("Organizador registrado con éxito.", "success")
        log_event(f"Usuario [{current_user.email}] registró al {rol} {cedula} en el evento {codigo_evento}.")
        return redirect(url_for('listar_participantes', codigo_evento=codigo_evento))

    return render_template('registrar_organizador.html',
        codigo_evento=codigo_evento,
        evento=evento,
        afiche_url=afiche_url
    )


###
### Listado de eventos próximos
###
@app.route('/tablero/eventos/proximos')
@app.route('/tablero/eventos/proximos/page/<int:page>')
@login_required
def listar_eventos_proximos(page=1):
    ahora = datetime.utcnow()
    inicio_hoy = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    eventos_por_pagina = 20

    # Contar el total de eventos próximos
    total_eventos = collection_eventos.count_documents({'fecha_inicio': {'$gte': inicio_hoy}})

    # Calcular el número total de páginas
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondear hacia arriba

    # Obtener los eventos próximos para la página actual
    eventos_cursor = collection_eventos.find({'fecha_inicio': {'$gte': inicio_hoy}}).sort('fecha_inicio').skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
    eventos = list(eventos_cursor)

    # Verificar si el usuario es organizador en cada evento
    for evento in eventos:
        es_organizador = collection_participantes.find_one({
            "codigo_evento": evento["codigo"],
            "cedula": str(current_user.cedula),
            "rol": "coorganizador"
        }) is not None 

        evento["es_organizador"] = es_organizador

    return render_template('eventos-proximos.html',
        eventos=eventos,
        page=page,
        total_paginas=total_paginas,
        total_eventos=total_eventos
    )



###
### Listado de eventos anteriores
###
@app.route('/tablero/eventos/anteriores')
@app.route('/tablero/eventos/anteriores/page/<int:page>')
@login_required
def listar_eventos_anteriores(page=1):
    ahora = datetime.utcnow()
    eventos_por_pagina = 20

    # Contar el total de eventos pasados
    total_eventos = collection_eventos.count_documents({"fecha_inicio": {"$lt": ahora}})
    # Calcular el número total de páginas
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondear hacia arriba

    # Obtener los eventos pasados para la página actual
    eventos_cursor = collection_eventos.find({"fecha_inicio": {"$lt": ahora}}).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
    eventos = list(eventos_cursor)

    # Verificar si el usuario es organizador en cada evento
    for evento in eventos:
        es_organizador = collection_participantes.find_one({
            "codigo_evento": evento["codigo"],
            "cedula": str(current_user.cedula),
            "rol": "coorganizador"
        }) is not None 

        evento["es_organizador"] = es_organizador

    return render_template('eventos-anteriores.html',
        eventos=eventos,
        page=page,
        total_paginas=total_paginas,
        total_eventos=total_eventos
    )


###
### Todos los eventos
###
@app.route('/tablero/eventos')
@app.route('/tablero/eventos/page/<int:page>')
@login_required
def listar_eventos(page=1):
    eventos_por_pagina = 20

    # Calcular el número total de eventos
    total_eventos = collection_eventos.count_documents({})
    # Calcular el número total de páginas
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondear hacia arriba

    # Obtener los eventos para la página actual
    eventos_cursor = collection_eventos.find().sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
    eventos = list(eventos_cursor)

    # Verificar si el usuario es organizador en cada evento
    for evento in eventos:
        es_organizador = collection_participantes.find_one({
            "codigo_evento": evento["codigo"],
            "cedula": str(current_user.cedula),
            "rol": "coorganizador"
        }) is not None 

        evento["es_organizador"] = es_organizador

    return render_template('eventos.html',
        eventos=eventos,
        total_eventos=total_eventos,
        page=page,
        total_paginas=total_paginas
    )


###
### Mis Eventos
###
@app.route('/tablero/eventos/mios')
@app.route('/tablero/eventos/mios/page/<int:page>')
@login_required
def mis_eventos(page=1):
    eventos_por_pagina = 20

    # Filtrar eventos donde el autor sea el usuario actual
    filtro = {"autor": current_user.id}

    # Calcular el número total de eventos del usuario
    total_eventos = collection_eventos.count_documents(filtro)
    # Calcular el número total de páginas
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondear hacia arriba

    # Obtener los eventos para la página actual
    eventos_cursor = collection_eventos.find(filtro).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
    eventos = list(eventos_cursor)

    # Verificar si el usuario es organizador en cada evento
    for evento in eventos:
        es_organizador = collection_participantes.find_one({
            "codigo_evento": evento["codigo"],
            "cedula": str(current_user.cedula),
            "rol": "coorganizador"
        }) is not None 

        evento["es_organizador"] = es_organizador

    return render_template('mis_eventos.html',
        eventos=eventos,
        total_eventos=total_eventos,
        page=page,
        total_paginas=total_paginas
    )


###
### Mis Eventos
###
@app.route('/tablero/eventos/mios/digitales')
@app.route('/tablero/eventos/mios/digitales/page/<int:page>')
@login_required
def mis_eventos_digitales(page=1):
    eventos_por_pagina = 20

    # Filtrar eventos donde el autor sea el usuario actual y modalidad != presencial
    filtro = {
        "autor": current_user.id,
        "modalidad": {"$ne": "Presencial"}
    }

    # Calcular el número total de eventos del usuario
    total_eventos = collection_eventos.count_documents(filtro)
    # Calcular el número total de páginas
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondear hacia arriba

    # Obtener los eventos para la página actual
    eventos_cursor = collection_eventos.find(filtro).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
    eventos = list(eventos_cursor)

    # Verificar si el usuario es organizador en cada evento
    for evento in eventos:
        es_organizador = collection_participantes.find_one({
            "codigo_evento": evento["codigo"],
            "cedula": str(current_user.cedula),
            "rol": "coorganizador"
        }) is not None 

        evento["es_organizador"] = es_organizador

    return render_template('mis_eventos_digitales.html',
        eventos=eventos,
        total_eventos=total_eventos,
        page=page,
        total_paginas=total_paginas
    )


###
### Administración de Colección de Eventos
###
@app.route('/tablero/bases-de-datos')
@app.route('/tablero/bases-de-datos/page/<int:page>')
@login_required
def db_eventos(page=1):
    # Verificar si el usuario es administrador
    if current_user.rol != 'administrador':
        flash('No tienes permiso para acceder a esta página.', 'error')
        return redirect(url_for('home'))

    eventos_por_pagina = 50
    skip = (page - 1) * eventos_por_pagina

    # Obtener todos los eventos
    eventos = list(collection_eventos.find().sort("fecha_inicio", -1).skip(skip).limit(eventos_por_pagina))
    total_eventos = collection_eventos.count_documents({})
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina

    # Obtener todos los campos posibles de la colección
    campos = set()
    for evento in eventos:
        campos.update(evento.keys())
    
    # Asegurar que campos importantes siempre estén presentes
    campos_importantes = ['codigo_evento', 'nombre', 'fecha_inicio', 'fecha_fin', 'estado_evento', 'unidad_ejecutora', 'tipo', 'modalidad', 'carga_horaria']
    campos.update(campos_importantes)
    
    campos = sorted(campos)  # ordenamos alfabéticamente para la tabla

    return render_template('bd.html',
        eventos=eventos,
        campos=campos,
        page=page,
        total_paginas=total_paginas,
        total_eventos=total_eventos)


###
### Actualizar campo de evento
###
@app.route('/actualizar_campo_evento', methods=['POST'])
@login_required
def actualizar_campo_evento():
    if current_user.rol != 'administrador':
        return jsonify({'success': False, 'error': 'No tienes permiso para realizar esta acción'})

    data = request.get_json()
    codigo_evento = data.get('codigo_evento')
    campo = data.get('campo')
    valor = data.get('valor', '')

    if not all([codigo_evento, campo]):
        return jsonify({'success': False, 'error': 'Faltan datos requeridos'})

    try:
        # Actualizar el campo específico
        result = collection_eventos.update_one(
            {'codigo': codigo_evento},  # Cambiado de codigo_evento a codigo
            {'$set': {campo: valor}}
        )

        if result.modified_count > 0 or result.matched_count > 0:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'No se pudo actualizar el campo'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


###
### Colección de participantes de evento
###
@app.route("/base-de-datos/<codigo_evento>")
def db_individual(codigo_evento):
    documentos = list(collection_participantes.find({"codigo_evento": codigo_evento}))
    total_registros = len(documentos)
    
    # Obtener el evento para mostrar su título
    evento = collection_eventos.find_one({"codigo_evento": codigo_evento})
    
    # Obtener todos los campos usados
    campos = set()
    for doc in documentos:
        campos.update(doc.keys())
    
    campos = sorted(campos)  # ordenamos alfabéticamente para la tabla
    
    return render_template("bd_individual.html", 
        codigo_evento=codigo_evento,
        campos=campos, 
        datos=documentos,
        total_registros=total_registros,
        evento=evento
    )


###
### Actualizar campo de participante
###
@app.route('/actualizar_campo_participante', methods=['POST'])
@login_required
def actualizar_campo_participante():
    if current_user.rol != 'administrador':
        return jsonify({'success': False, 'error': 'No tienes permiso para realizar esta acción'})

    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No se recibieron datos JSON'})

        nanoid = data.get('nanoid')
        campo = data.get('campo')
        valor = data.get('valor', '')

        print(f"Recibida solicitud para actualizar: nanoid={nanoid}, campo={campo}, valor={valor}")

        if not all([nanoid, campo]):
            return jsonify({'success': False, 'error': 'Faltan datos requeridos'})

        # Verificar si el participante existe
        participante = collection_participantes.find_one({'nanoid': nanoid})
        if not participante:
            return jsonify({'success': False, 'error': 'Participante no encontrado'})

        # Actualizar el campo específico
        result = collection_participantes.update_one(
            {'nanoid': nanoid},
            {'$set': {campo: valor}}
        )

        #print(f"Resultado de la actualización: modified={result.modified_count}, matched={result.matched_count}")

        if result.modified_count > 0 or result.matched_count > 0:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'No se pudo actualizar el campo'})

    except Exception as e:
        print(f"Error en actualizar_campo_participante: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})


###
### Eliminar participante desde vista de BD
###
@app.route('/eliminar_participante_bd/<codigo_evento>/<id_participante>', methods=['POST'])
@login_required
def eliminar_participante_bd(codigo_evento, id_participante):
    if current_user.rol != 'administrador':
        flash('No tienes permisos para eliminar participantes.', 'error')
        return redirect(url_for('db_individual', codigo_evento=codigo_evento))

    try:
        participante = collection_participantes.find_one({'_id': ObjectId(id_participante), 'codigo_evento': codigo_evento})
    except Exception:
        participante = None
    if participante:
        collection_participantes.delete_one({'_id': ObjectId(id_participante), 'codigo_evento': codigo_evento})
        flash('Participante eliminado correctamente.', 'success')
    else:
        flash('Participante no encontrado.', 'error')
    return redirect(url_for('db_individual', codigo_evento=codigo_evento))


###
### Aula Digital
###
@app.route('/tablero/eventos/digitales')
@app.route('/tablero/eventos/digitales/page/<int:page>')
@login_required
def listar_eventos_digitales(page=1):
    eventos_por_pagina = 20

    # Filtrar eventos que no sean presenciales
    filtro = {"modalidad": {"$ne": "Presencial"}}

    # Calcular el número total de eventos que cumplen la condición
    total_eventos = collection_eventos.count_documents(filtro)
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina  # Redondeo hacia arriba

    # Obtener los eventos que cumplen la condición para la página actual
    eventos_cursor = (
        collection_eventos.find(filtro)
        .sort("fecha_inicio", -1)
        .skip((page - 1) * eventos_por_pagina)
        .limit(eventos_por_pagina)
    )
    eventos = list(eventos_cursor)

    # Verificar si el usuario es organizador en cada evento
    for evento in eventos:
        es_organizador = collection_participantes.find_one({
            "codigo_evento": evento["codigo"],
            "cedula": str(current_user.cedula),
            "rol": "coorganizador"
        }) is not None 

        evento["es_organizador"] = es_organizador

    return render_template(
        'aula_digital.html',
        eventos=eventos,
        total_eventos=total_eventos,
        page=page,
        total_paginas=total_paginas
    )


###
### Listado de participantes de un evento
###
@app.route('/tablero/eventos/<codigo_evento>/participantes')
@login_required
def listar_participantes(codigo_evento):
    # Recuperar participantes registrados para el evento específico
    evento = collection_eventos.find_one({"codigo": codigo_evento})

    participantes_cursor = collection_participantes.find({"codigo_evento": codigo_evento})

    total_participantes = collection_participantes.count_documents({"codigo_evento": codigo_evento, "rol": "participante"})
    total_ponentes = collection_participantes.count_documents({"codigo_evento": codigo_evento, "rol": "ponente"})

    participantes = list(participantes_cursor)

    # Convertir el campo timestamp a datetime si es una cadena
    for participante in participantes:
        if isinstance(participante.get('timestamp'), str):
            try:
                participante['timestamp'] = datetime.fromisoformat(participante['timestamp'].replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                # Si hay un error en la conversión, establecer la fecha actual
                participante['timestamp'] = datetime.now()

    estado_evento = evento.get('estado_evento', 'borrador')

    es_organizador = collection_participantes.find_one({
        "codigo_evento": codigo_evento,
        "cedula": str(current_user.cedula),
        "rol": "coorganizador"
    }) is not None

    return render_template('participantes.html',
        participantes=participantes,
        total_participantes=total_participantes,
        total_ponentes=total_ponentes,
        evento=evento,
        nombre_evento=evento['nombre'],
        estado_evento=estado_evento,
        es_organizador=es_organizador,
    )


###
### Exportar participantes en CSV
###
from flask import make_response
import csv
import io

PERFILES_MAP = {
    "medico_general": "Médico General - Consulta Externa",
    "medico_urgencias": "Médico General - Urgencias",
    "medico_especialista": "Médico Especialista",
    "odontologo": "Odontólogo(a)",
    "odontologo_especialista": "Odontólogo(a) Especialista",
    "enfermero": "Enfermera(o)",
    "tecnico_enfermeria": "Técnico en Enfermería",
    "laboratorista": "Laboratorista",
    "tecnico_laboratorio": "Técnico de Laboratorio",
    "farmaceutico": "Farmacéutico(a)",
    "tecnico_farmacia": "Técnico de Farmacia",
    "reges": "Estadístico de Salud",
    "fisioterapeuta": "Fisioterapeuta",
    "fonoaudiologo": "Fonoaudiólogo(a)",
    "psicologo": "Psicólogo(a)",
    "nutricionista": "Nutricionista",
    "estudiante_salud": "Estudiante",
    "administrativo": "Administrativo",
    "otro": "Otro"
}

REGION_MAP = {
    "panama": "Panamá Metro",
    "sanmiguelito": "San Miguelito",
    "panamaoeste": "Panamá Oeste",
    "panamaeste": "Panamá Este",
    "bocasdeltoro": "Bocas del Toro",
    "cocle": "Coclé",
    "colon": "Colón",
    "chiriqui": "Chiriquí",
    "herrera": "Herrera",
    "lossantos": "Los Santos",
    "veraguas": "Veraguas"
}

@app.route('/tablero/eventos/<codigo_evento>/participantes/exportar_csv')
@login_required
def exportar_csv(codigo_evento):
    # Recuperar participantes registrados para el evento específico
    participantes_cursor = collection_participantes.find({"codigo_evento": codigo_evento})
    participantes = list(participantes_cursor)

    # Crear un archivo CSV en memoria
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')  # se cambia a ; por excel...


    # Escribir la cabecera del CSV
    writer.writerow(['Nombre', 'Apellido', 'Cédula', 'Rol', 'Perfil', 'Región', 'Unidad Ejecutora'])

    # Escribir los datos de los participantes
    for participante in participantes:

        perfil = PERFILES_MAP.get(participante.get('perfil', 'N/A'), participante.get('perfil', 'N/A'))

        region = REGION_MAP.get(participante.get('region', 'N/A'), participante.get('region', 'N/A'))

        writer.writerow([
            participante.get('nombres', 'N/A'),
            participante.get('apellidos', 'N/A'),
            participante.get('cedula', 'N/A'),
            participante.get('rol', 'N/A'),
            perfil,
            region,
            participante.get('unidad', 'N/A')
        ])

    # Preparar la respuesta para descargar el archivo CSV
    output.seek(0)
    bom = '\ufeff'  # BOM para UTF-8, este hack es para que excel reconozca el csv como utf-8
    csv_with_bom = bom + output.getvalue()
    
    response = make_response(csv_with_bom)
    response.headers['Content-Disposition'] = f'attachment; filename={codigo_evento}_participantes.csv'
    response.headers['Content-type'] = 'text/csv; charset=utf-8'

    return response


###
### Formulario de creación de evento
###
@app.route('/tablero/eventos/nuevo', methods=['GET', 'POST'])
@login_required
def crear_evento():
    if request.method == 'POST':
        nombre = request.form['nombre']
        region = request.form['region']
        unidad_ejecutora = request.form['unidad_ejecutora']
        lugar = request.form['lugar']
        tipo = request.form['tipo']
        cupos = request.form['cupos']
        carga_horaria = request.form['carga_horaria']
        modalidad = request.form['modalidad']
        descripcion = request.form['descripcion']

        fecha_inicio_str = request.form['fecha_inicio']
        fecha_fin_str = request.form['fecha_fin']

        fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%d')
        fecha_fin = datetime.strptime(fecha_fin_str, '%Y-%m-%d')

        estado_evento = request.form['estado_evento']

        timestamp = request.form['timestamp']

        # Obtener un código único
        codigo = obtener_codigo_unico()

        # Carga de archivos
        afiche_file = request.files.get('afiche_evento')
        fondo_file = request.files.get('fondo_evento')
        programa_file = request.files.get('programa_evento')
        certificado_file = request.files.get('certificado_evento')

        afiche_path = None
        fondo_path = None
        programa_path = None
        certificado_path = None

        if afiche_file:
            afiche_filename = f"{codigo}-afiche.jpg"
            afiche_path = os.path.join(app.config['UPLOAD_FOLDER'], afiche_filename)

            # Convertir y guardar la imagen como JPG
            image = Image.open(afiche_file)
            image.convert('RGB').save(afiche_path, 'JPEG')  # Convertir a JPG y guardar

            # Redimensionar la imagen a 750x750 píxeles
            image.thumbnail((750, 750))  # Mantiene la relación de aspecto
            resized_afiche_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{codigo}-afiche-750.jpg")
            image.save(resized_afiche_path, 'JPEG')  # Guardar la versión redimensionada
            print(f"Archivo afiche guardado en: {afiche_path}")  # Confirmación
            print(f"Archivo afiche redimensionado guardado en: {resized_afiche_path}")  # Confirmación

        if fondo_file:
            fondo_filename = f"{codigo}-fondo.jpg"
            fondo_path = os.path.join(app.config['UPLOAD_FOLDER'], fondo_filename)

            # Convertir y guardar la imagen como JPG
            image = Image.open(fondo_file)
            image.convert('RGB').save(fondo_path, 'JPEG')  # Convertir a JPG y guardar
            print(f"Archivo fondo guardado en: {fondo_path}")  # Confirmación

        if programa_file:
            programa_filename = f"{codigo}-programa.pdf"
            programa_path = os.path.join(app.config['UPLOAD_FOLDER'], programa_filename)
            programa_file.save(programa_path)

        if certificado_file:
            certificado_filename = f"{codigo}-certificado.pdf"
            certificado_path = os.path.join(app.config['UPLOAD_FOLDER'], certificado_filename)
            certificado_file.save(certificado_path)

        # Insertar nuevo evento en la colección
        collection_eventos.insert_one({
            'nombre': nombre,
            'codigo': codigo,
            'region': region,
            'unidad_ejecutora': unidad_ejecutora,
            'lugar': lugar,
            'tipo': tipo,
            'modalidad': modalidad,
            'descripcion': descripcion,
            'cupos': cupos,
            'carga_horaria': carga_horaria,
            'fecha_inicio': fecha_inicio,
            'fecha_fin': fecha_fin,
            'estado_evento': estado_evento,
            'afiche': afiche_path if afiche_file else None,
            'afiche_750': resized_afiche_path if afiche_file else None,
            'fondo': fondo_path if fondo_file else None,
            'programa': programa_path if programa_file else None,
            'certificado': certificado_path if certificado_file else None,
            'timestamp': timestamp,
            'autor': current_user.id
        })
        log_event(f"Usuario [{current_user.email}] ha creado el evento {codigo} exitosamente.")
        return redirect(url_for('mis_eventos'))  # Redirigir a la lista de eventos

    return render_template('crear_evento.html')


###
### Ver detalles de evento
###
@app.route('/tablero/eventos/<codigo_evento>')
@login_required
def ver_evento(codigo_evento):
    # Obtener el evento actual de la base de datos
    evento = collection_eventos.find_one({"codigo": codigo_evento})

    return render_template('ver_evento.html', evento=evento)


###
### Editar evento
###
@app.route('/tablero/eventos/<codigo_evento>/editar', methods=['GET', 'POST'])
@login_required
def editar_evento(codigo_evento):
    # Obtener el evento actual de la base de datos
    evento = collection_eventos.find_one({"codigo": codigo_evento})

    if not evento:
        flash("Evento no encontrado", "danger")
        return redirect(url_for('listar_eventos'))

    if request.method == 'POST':
        # Recoger los datos del formulario
        nombre = request.form['nombre']
        region = request.form['region']
        unidad_ejecutora = request.form['unidad_ejecutora']
        lugar = request.form['lugar']
        tipo = request.form['tipo']
        modalidad = request.form['modalidad']
        descripcion = request.form['descripcion']
        cupos = request.form['cupos']
        carga_horaria = request.form['carga_horaria']
        fecha_inicio_str = request.form['fecha_inicio']
        fecha_fin_str = request.form['fecha_fin']

        fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%d')
        fecha_fin = datetime.strptime(fecha_fin_str, '%Y-%m-%d')

        estado_evento = request.form['estado_evento']

        timestamp = request.form['timestamp']

        # Carga de archivos (opcional)
        afiche_file = request.files.get('afiche_evento')
        fondo_file = request.files.get('fondo_evento')
        programa_file = request.files.get('programa_evento')
        certificado_file = request.files.get('certificado_evento')

        afiche_path = evento.get('afiche')
        fondo_path = evento.get('fondo')
        resized_afiche_path = evento.get('afiche_750')
        programa_path = evento.get('programa')
        certificado_path = evento.get('certificado')

        if afiche_file:
            afiche_filename = f"{codigo_evento}-afiche.jpg"
            afiche_path = os.path.join(app.config['UPLOAD_FOLDER'], afiche_filename)

            # Convertir y guardar la imagen como JPG
            image = Image.open(afiche_file)
            image.convert('RGB').save(afiche_path, 'JPEG')  # Convertir a JPG y guardar

            # Redimensionar la imagen a 750x750 píxeles
            image.thumbnail((750, 750))  # Mantiene la relación de aspecto
            resized_afiche_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{codigo_evento}-afiche-750.jpg")
            image.save(resized_afiche_path, 'JPEG')  # Guardar la versión redimensionada

        if fondo_file:
            fondo_filename = f"{codigo_evento}-fondo.jpg"
            fondo_path = os.path.join(app.config['UPLOAD_FOLDER'], fondo_filename)

            # Convertir y guardar la imagen como JPG
            image = Image.open(fondo_file)
            image.convert('RGB').save(fondo_path, 'JPEG')  # Convertir a JPG y guardar

        if programa_file:
            programa_filename = f"{codigo_evento}-programa.pdf"
            programa_path = os.path.join(app.config['UPLOAD_FOLDER'], programa_filename)
            programa_file.save(programa_path)

        if certificado_file:
            certificado_filename = f"{codigo_evento}-certificado.pdf"
            certificado_path = os.path.join(app.config['UPLOAD_FOLDER'], certificado_filename)
            certificado_file.save(certificado_path)

        # Actualizar el evento en la base de datos
        collection_eventos.update_one(
            {"codigo": codigo_evento},
            {"$set": {
                'nombre': nombre,
                'region': region,
                'unidad_ejecutora': unidad_ejecutora,
                'lugar': lugar,
                'tipo': tipo,
                'modalidad': modalidad,
                'descripcion': descripcion,
                'cupos': cupos,
                'carga_horaria': carga_horaria,
                'fecha_inicio': fecha_inicio,
                'fecha_fin': fecha_fin,
                'estado_evento': estado_evento,
                'afiche': afiche_path,
                'afiche_750': resized_afiche_path,
                'fondo': fondo_path,
                'programa': programa_path,
                'certificado': certificado_path,
            }}
        )

        log_event(f"Usuario [{current_user.email}] ha editado el evento {codigo_evento}.")
        return redirect(url_for('mis_eventos'))  # Redirigir a la lista de eventos

    return render_template('editar_evento.html', evento=evento)


###
### Eliminar archivos adjuntos del evento
###
@app.route('/eliminar_archivo_evento/<codigo_evento>/<tipo_archivo>', methods=['POST'])
@login_required
def eliminar_archivo_evento(codigo_evento, tipo_archivo):
    # Obtener el evento actual de la base de datos
    evento = collection_eventos.find_one({"codigo": codigo_evento})

    if not evento:
        flash("Evento no encontrado", "error")
        return redirect(url_for('listar_eventos'))

    # Determinar qué archivo eliminar basado en el tipo
    archivo_path = None
    campo_db = None
    
    if tipo_archivo == 'afiche':
        archivo_path = evento.get('afiche')
        archivo_750_path = evento.get('afiche_750')
        campo_db = 'afiche'
        campo_750_db = 'afiche_750'
    elif tipo_archivo == 'fondo':
        archivo_path = evento.get('fondo')
        campo_db = 'fondo'
    elif tipo_archivo == 'programa':
        archivo_path = evento.get('programa')
        campo_db = 'programa'
    elif tipo_archivo == 'certificado':
        archivo_path = evento.get('certificado')
        campo_db = 'certificado'
    else:
        flash("Tipo de archivo no válido", "error")
        return redirect(url_for('editar_evento', codigo_evento=codigo_evento))

    # Eliminar el archivo físico si existe
    if archivo_path and os.path.exists(archivo_path):
        try:
            os.remove(archivo_path)
            log_event(f"Usuario [{current_user.email}] ha eliminado el afiche de evento: {archivo_path}.")
        except Exception as e:
            flash(f"Error al eliminar el archivo: {str(e)}", "error")
            log_event(f"Error al eliminar archivo físico {archivo_path}: {str(e)}")
            return redirect(url_for('editar_evento', codigo_evento=codigo_evento))

    # Eliminar el archivo redimensionado si existe (solo para afiche)
    if tipo_archivo == 'afiche' and archivo_750_path and os.path.exists(archivo_750_path):
        try:
            os.remove(archivo_750_path)
            log_event(f"Usuario [{current_user.email}] ha eliminado el afiche de evento redimensionado: {archivo_750_path}.")
        except Exception as e:
            flash(f"Error al eliminar el archivo redimensionado: {str(e)}", "error")
            log_event(f"Error al eliminar archivo redimensionado {archivo_750_path}: {str(e)}")
            return redirect(url_for('editar_evento', codigo_evento=codigo_evento))

    # Actualizar la base de datos
    update_data = {campo_db: None}
    if tipo_archivo == 'afiche':
        update_data[campo_750_db] = None

    try:
        result = collection_eventos.update_one(
            {"codigo": codigo_evento},
            {"$set": update_data}
        )
        
        if result.modified_count == 0:
            flash("Error al actualizar la base de datos", "error")
            log_event(f"Error: No se pudo actualizar la base de datos para el evento {codigo_evento}")
            return redirect(url_for('editar_evento', codigo_evento=codigo_evento))
            
        log_event(f"Usuario [{current_user.email}] ha actualizado el evento {codigo_evento}: {update_data}.")
    except Exception as e:
        flash(f"Error al actualizar la base de datos: {str(e)}", "error")
        log_event(f"Error al actualizar la base de datos para el evento {codigo_evento}: {str(e)}")
        return redirect(url_for('editar_evento', codigo_evento=codigo_evento))

    flash(f"Archivo {tipo_archivo} eliminado exitosamente", "success")
    return redirect(url_for('editar_evento', codigo_evento=codigo_evento))


###
### Resumen de evento
###
@app.route('/resumen/<codigo_evento>')
def resumen_evento(codigo_evento):
    evento = collection_eventos.find_one({"codigo": codigo_evento})

    if not evento:
        abort(404)

    return render_template('resumen_evento.html', evento=evento)


###
###
###
@app.route('/tablero/eventos/<codigo_evento>/cerrar', methods=['POST'])
@login_required
def cerrar_evento(codigo_evento):
    # Actualizar el estado del evento a "cerrado"
    collection_eventos.update_one(
        {"codigo": codigo_evento},
        {"$set": {"estado_evento": "cerrado"}}
    )
    log_event(f"Usuario [{current_user.email}] cerró el evento {codigo_evento}.")
    return redirect(url_for('listar_eventos'))  # Redirigir a la lista de eventos


###
### Validación para eliminar evento
###
@app.route('/tablero/eventos/<codigo_evento>/eliminar', methods=['POST'])
@login_required
def eliminar_evento(codigo_evento):
    # Verificar si hay participantes asociados al evento
    if collection_participantes.find_one({"codigo_evento": codigo_evento}) is not None:
        log_event(f"Usuario [{current_user.email}] intentó eliminar el evento {codigo_evento} con usuarios asociados.")
        return "No se puede eliminar el evento porque tiene participantes asociados.", 400

    # Si no hay participantes, eliminar el evento
    collection_eventos.delete_one({"codigo": codigo_evento})
    log_event(f"Usuario [{current_user.email}] eliminó el evento {codigo_evento}.")
    return redirect(url_for('listar_eventos'))  # Redirigir a la lista de eventos


###
### Eliminar participante
###
@app.route('/eliminar_participante/<nanoid>', methods=['POST'])
@login_required
def eliminar_participante(nanoid):
    participante = collection_participantes.find_one({"nanoid": nanoid})

    if participante:
        log_event(f"Usuario [{current_user.email}] eliminó al {participante['rol']} {participante['cedula']} del evento {participante['codigo_evento']}.")
        result = collection_participantes.delete_one({"nanoid": nanoid})
        return redirect(url_for('listar_participantes', codigo_evento=participante['codigo_evento']))

    else:
        log_event(f"Usuario [{current_user.email}] intentó eliminar un participante que no existe con nanoid {nanoid}")
        return redirect(url_for('listar_participantes', codigo_evento=''))


###
### Página de evento
###
@app.route('/evento/<codigo_evento>', methods=['GET'])
def mostrar_evento(codigo_evento):

    evento = collection_eventos.find_one({"codigo": codigo_evento})

    if evento:

        qr_path = generate_qr_code(codigo_evento)

        # Generar un nuevo OTP si no existe o ha expirado
        if codigo_evento not in otp_storage or datetime.now() >= otp_storage[codigo_evento]['valid_until']:
            otp_code = generate_otp()
            otp_storage[codigo_evento] = {
                'code': otp_code,
                'valid_until': datetime.now() + timedelta(minutes=1)
            }
        else:
            otp_code = otp_storage[codigo_evento]['code']

        return render_template('evento-individual.html', evento=evento, otp=otp_code)
    else:
        return "Evento no encontrado", 404


###
### QR evento
###
import qrcode
from flask import send_file

def generate_qr_code(codigo_evento):
    qr_path = f"static/uploads/{codigo_evento}-qr.png"

    if not os.path.exists(qr_path):
        base_url = app.config['BASE_URL']
        url = f"{base_url}registrar_participante/{codigo_evento}"
        qr = qrcode.make(url)
        qr.save(qr_path)

    return qr_path


###
### Validación de certificados
###
@app.route('/validar_certificado', methods=['GET', 'POST'])
def validar_certificado():
    if request.method == 'POST':
        nanoid = request.form['nanoid']

        participante = collection_participantes.find_one({"nanoid": nanoid})

        if participante:

            evento = collection_eventos.find_one({"codigo": participante['codigo_evento']})

            if evento:
                return render_template('certificado_valido.html', participante=participante, evento=evento)
            else:
                return render_template('certificado_invalido.html')
        else:
            return render_template('certificado_invalido.html', nanoid=nanoid)

    return render_template('validar.html')


###
### Función para ordenar eventos 
###
def obtener_fecha_ordenable(item):
    fecha = item.get('fecha_evento')
    if not fecha:
        return datetime.min  # Para que los eventos sin fecha aparezcan al inicio o final
        # Asume que la fecha está en formato string como '2023-04-15'
        # Ajustar formato según cómo estén almacenadas fechas
    try:
        return datetime.strptime(fecha, '%Y-%m-%d')
    except (ValueError, TypeError):
        return datetime.min


###
### listado de resultados 
###
from app.auth import generate_token
@app.route('/buscar_certificados', methods=['GET', 'POST'])
def buscar_certificados():
    if request.method == 'POST':
        # Obtener la cédula del formulario
        cedula = request.form.get('cedula')
        token = generate_token(cedula)

        # Buscar registros del participante
        participantes = list(collection_participantes.find({"cedula": cedula}))

        if not participantes:
            return render_template('lista_certificados.html', cedula=cedula, resultados=None)

        resultados = []

        for participante in participantes:
            codigo_evento = participante.get('codigo_evento')
            evento = collection_eventos.find_one({"codigo": codigo_evento})

            tiene_archivos = collection_repositorio.count_documents({'codigo_evento': codigo_evento}) > 0

            if evento:
                fecha_evento = evento.get('fecha_fin', None)

                resultado = {
                    'nombres': participante['nombres'],
                    'apellidos': participante['apellidos'],
                    'cedula': participante['cedula'],
                    'nanoid': participante['nanoid'],
                    'rol': participante['rol'],
                    'ponencia': participante.get('titulo_ponencia', 'N/A'),
                    'codigo_evento': codigo_evento,
                    'certificado_evento': evento.get('certificado', None),
                    'titulo_evento': evento.get('nombre', 'Título no disponible'),
                    'fecha_evento': fecha_evento,
                    'modalidad_evento': evento.get('modalidad', 'No disponible'),
                    'tiene_archivos': tiene_archivos,
                }
                resultados.append(resultado)
            else:
                resultado = {
                    'cedula': participante['cedula'],
                    'nanoid': participante['nanoid'],
                    'codigo_evento': codigo_evento,
                    'titulo_evento': 'Evento no encontrado',
                    'fecha_evento': None
                }
                resultados.append(resultado)

        # ========= FILTRAR DUPLICADOS DE PARTICIPANTE ==========
        filtrados = []
        unicos_participantes = {}

        for r in resultados:
            if r['rol'] == 'participante':
                clave = (r['cedula'], r['codigo_evento'], r['rol'])
                if clave not in unicos_participantes:
                    unicos_participantes[clave] = r
            else:
                filtrados.append(r)

        # Añadir los únicos registros de participante
        filtrados.extend(unicos_participantes.values())
        resultados = filtrados
        # ========================================================

        # Ordenar por fecha del evento
        fecha_actual = datetime.now().date()
        hora_actual = datetime.now().time()

        def obtener_fecha_ordenable(item):
            fecha = item.get('fecha_evento')
            return fecha or datetime.min

        resultados.sort(key=obtener_fecha_ordenable, reverse=True)

        return render_template(
            'lista_certificados.html',
            cedula=cedula,
            resultados=resultados,
            fecha_actual=fecha_actual,
            hora_actual=hora_actual,
            token=token
        )

    return render_template('buscar.html')


###
### Plantilla varias
###
@app.route('/tablero/plantillas')
@login_required
def plantillas():
    return render_template('plantillas.html', active_section='plantillas')


###
### Herramientas
###
@app.route('/tablero/herramientas')
@login_required
def herramientas():
    return render_template('herramientas.html', active_section='herramientas')


###
###
###
###
### Plantilla varias
###
@app.route('/tablero/metricas')
@app.route('/tablero/metricas/page/<int:page>')
@login_required
def tablero_metricas(page=1):

    # Obtener el número total de usuarios
    total_usuarios = collection_usuarios.count_documents({"rol": {"$ne": "administrador"}})
    # Obtener el número total de eventos
    total_eventos = collection_eventos.count_documents({})
    # Obtener el número total de eventos cerrados
    total_eventos_cerrados = collection_eventos.count_documents({"estado_evento": "cerrado"})
    # Contar el número total de ponentes
    total_ponentes = collection_participantes.count_documents({"rol": "ponente"})
    # Contar el número total de participantes
    total_participantes = collection_participantes.count_documents({"rol": "participante"})

    ## Tablero de Métricas de Eventos
    eventos_por_pagina = 20
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina

    # Obtener los eventos con estado cerrado para la página actual
    eventos_cursor = collection_eventos.find(
        {"estado_evento": "cerrado"}
    ).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
    
    eventos = list(eventos_cursor)

    # Verificar si el usuario es organizador en cada evento
    for evento in eventos:
        es_organizador = collection_participantes.find_one({
            "codigo_evento": evento["codigo"],
            "cedula": str(current_user.cedula),
            "rol": "coorganizador"
        }) is not None 

        evento["es_organizador"] = es_organizador

        # Añade métricas específicas de cada evento
        codigo_evento = evento["codigo"]
        
        # Total de participantes en este evento
        evento["total_participantes"] = collection_participantes.count_documents({
            "codigo_evento": codigo_evento,
            "rol": "participante"
        })
        
        # Total de ponentes en este evento
        evento["total_ponentes"] = collection_participantes.count_documents({
            "codigo_evento": codigo_evento, 
            "rol": "ponente"
        })

    return render_template(
        'metricas.html',
        active_section='metricas',
        page=page,
        total_paginas=total_paginas,
        total_usuarios=total_usuarios,
        total_eventos=total_eventos,
        total_eventos_cerrados=total_eventos_cerrados,
        total_ponentes=total_ponentes,
        total_participantes=total_participantes,
        eventos=eventos,
    )


###
### LMS Metrics Dashboard - General
###
@app.route('/tablero/metricas/lms')
@app.route('/tablero/metricas/lms/page/<int:page>')
@login_required
def tablero_metricas_lms(page=1):
    
    # Filtrar eventos con modalidad Virtual asincrónica
    eventos_lms_query = {"modalidad": "Virtual asincrónica"}
    
    # Obtener métricas generales de LMS
    total_eventos_lms = collection_eventos.count_documents(eventos_lms_query)
    total_eventos_lms_cerrados = collection_eventos.count_documents({
        **eventos_lms_query, 
        "estado_evento": "cerrado"
    })
    
    # Contar participantes en eventos LMS
    eventos_lms = list(collection_eventos.find(eventos_lms_query, {"codigo": 1}))
    codigos_eventos_lms = [evento["codigo"] for evento in eventos_lms]
    
    total_participantes_lms = collection_participantes.count_documents({
        "codigo_evento": {"$in": codigos_eventos_lms},
        "rol": "participante"
    })
    
    # Contar exámenes realizados
    total_examenes_realizados = collection_exam_results.count_documents({
        "codigo_evento": {"$in": codigos_eventos_lms}
    })
    
    # Calcular promedio de intentos por examen
    pipeline_intentos = [
        {"$match": {"codigo_evento": {"$in": codigos_eventos_lms}}},
        {"$group": {
            "_id": None,
            "promedio_intentos": {"$avg": "$numero_intento"}
        }}
    ]
    resultado_intentos = list(collection_exam_results.aggregate(pipeline_intentos))
    promedio_intentos = round(resultado_intentos[0]["promedio_intentos"], 2) if resultado_intentos else 0
    
    # Calcular promedio de calificaciones
    pipeline_calificaciones = [
        {"$match": {"codigo_evento": {"$in": codigos_eventos_lms}}},
        {"$group": {
            "_id": None,
            "promedio_calificacion": {"$avg": "$calificacion"}
        }}
    ]
    resultado_calificaciones = list(collection_exam_results.aggregate(pipeline_calificaciones))
    promedio_calificacion = round(resultado_calificaciones[0]["promedio_calificacion"], 2) if resultado_calificaciones else 0
    
    # Paginación para eventos LMS
    eventos_por_pagina = 20
    total_paginas = (total_eventos_lms_cerrados + eventos_por_pagina - 1) // eventos_por_pagina
    
    # Obtener eventos LMS cerrados para la página actual
    eventos_cursor = collection_eventos.find({
        **eventos_lms_query,
        "estado_evento": "cerrado"
    }).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
    
    eventos = list(eventos_cursor)
    
    # Añadir métricas específicas para cada evento
    for evento in eventos:
        codigo_evento = evento["codigo"]
        
        # Verificar si el usuario es organizador
        es_organizador = collection_participantes.find_one({
            "codigo_evento": codigo_evento,
            "cedula": str(current_user.cedula),
            "rol": "coorganizador"
        }) is not None
        evento["es_organizador"] = es_organizador
        
        # Métricas de participantes
        evento["total_participantes"] = collection_participantes.count_documents({
            "codigo_evento": codigo_evento,
            "rol": "participante"
        })
        
        # Métricas de exámenes
        evento["total_examenes"] = collection_eva.count_documents({
            "codigo_evento": codigo_evento,
            "tipo": "examen"
        })
        
        evento["total_resultados_examenes"] = collection_exam_results.count_documents({
            "codigo_evento": codigo_evento
        })
        
        # Promedio de calificación para este evento
        pipeline_evento = [
            {"$match": {"codigo_evento": codigo_evento}},
            {"$group": {
                "_id": None,
                "promedio": {"$avg": "$calificacion"}
            }}
        ]
        resultado_evento = list(collection_exam_results.aggregate(pipeline_evento))
        evento["promedio_calificacion"] = round(resultado_evento[0]["promedio"], 2) if resultado_evento else 0
    
    return render_template(
        'metricas_lms.html',
        active_section='metricas',
        page=page,
        total_paginas=total_paginas,
        total_eventos_lms=total_eventos_lms,
        total_eventos_lms_cerrados=total_eventos_lms_cerrados,
        total_participantes_lms=total_participantes_lms,
        total_examenes_realizados=total_examenes_realizados,
        promedio_intentos=promedio_intentos,
        promedio_calificacion=promedio_calificacion,
        eventos=eventos,
    )


###
### LMS Metrics Dashboard - Specific Event
###
@app.route('/tablero/metricas/lms/<codigo_evento>')
@login_required
def tablero_metricas_lms_evento(codigo_evento):
    
    # Verificar que el evento existe y es Virtual asincrónica
    evento = collection_eventos.find_one({
        "codigo": codigo_evento,
        "modalidad": "Virtual asincrónica"
    })
    
    if not evento:
        abort(404)
    
    # Verificar si el usuario es organizador
    es_organizador = collection_participantes.find_one({
        "codigo_evento": codigo_evento,
        "cedula": str(current_user.cedula),
        "rol": "coorganizador"
    }) is not None
    
    # Métricas generales del evento
    total_participantes = collection_participantes.count_documents({
        "codigo_evento": codigo_evento,
        "rol": "participante"
    })
    
    total_examenes = collection_eva.count_documents({
        "codigo_evento": codigo_evento,
        "tipo": "examen"
    })
    
    total_resultados = collection_exam_results.count_documents({
        "codigo_evento": codigo_evento
    })
    
    # Métricas de calificaciones
    pipeline_calificaciones = [
        {"$match": {"codigo_evento": codigo_evento}},
        {"$group": {
            "_id": None,
            "promedio": {"$avg": "$calificacion"},
            "maximo": {"$max": "$calificacion"},
            "minimo": {"$min": "$calificacion"}
        }}
    ]
    resultado_calificaciones = list(collection_exam_results.aggregate(pipeline_calificaciones))
    
    if resultado_calificaciones:
        promedio_calificacion = round(resultado_calificaciones[0]["promedio"], 2)
        calificacion_maxima = resultado_calificaciones[0]["maximo"]
        calificacion_minima = resultado_calificaciones[0]["minimo"]
    else:
        promedio_calificacion = 0
        calificacion_maxima = 0
        calificacion_minima = 0
    
    # Distribución de calificaciones
    pipeline_distribucion = [
        {"$match": {"codigo_evento": codigo_evento}},
        {"$bucket": {
            "groupBy": "$calificacion",
            "boundaries": [0, 60, 70, 80, 90, 100],
            "default": "100+",
            "output": {"count": {"$sum": 1}}
        }}
    ]
    distribucion_calificaciones = list(collection_exam_results.aggregate(pipeline_distribucion))
    
    # Métricas de intentos
    pipeline_intentos = [
        {"$match": {"codigo_evento": codigo_evento}},
        {"$group": {
            "_id": "$cedula_participante",
            "total_intentos": {"$max": "$numero_intento"},
            "mejor_calificacion": {"$max": "$calificacion"}
        }}
    ]
    datos_participantes = list(collection_exam_results.aggregate(pipeline_intentos))
    
    # Promedio de intentos por participante
    promedio_intentos = round(sum(p["total_intentos"] for p in datos_participantes) / len(datos_participantes), 2) if datos_participantes else 0
    
    # Participantes que han realizado exámenes
    participantes_con_examenes = len(datos_participantes)
    
    # Obtener detalles de exámenes del evento
    examenes = list(collection_eva.find({
        "codigo_evento": codigo_evento,
        "tipo": "examen"
    }).sort("orden", 1))
    
    # Añadir estadísticas por examen
    for examen in examenes:
        examen_resultados = collection_exam_results.count_documents({
            "codigo_evento": codigo_evento,
            "orden_examen": examen["orden"]
        })
        examen["total_resultados"] = examen_resultados
        
        # Promedio de calificación para este examen específico
        pipeline_examen = [
            {"$match": {
                "codigo_evento": codigo_evento,
                "orden_examen": examen["orden"]
            }},
            {"$group": {
                "_id": None,
                "promedio": {"$avg": "$calificacion"}
            }}
        ]
        resultado_examen = list(collection_exam_results.aggregate(pipeline_examen))
        examen["promedio_calificacion"] = round(resultado_examen[0]["promedio"], 2) if resultado_examen else 0
    
    return render_template(
        'metricas_lms_evento.html',
        active_section='metricas',
        evento=evento,
        es_organizador=es_organizador,
        total_participantes=total_participantes,
        total_examenes=total_examenes,
        total_resultados=total_resultados,
        promedio_calificacion=promedio_calificacion,
        calificacion_maxima=calificacion_maxima,
        calificacion_minima=calificacion_minima,
        distribucion_calificaciones=distribucion_calificaciones,
        promedio_intentos=promedio_intentos,
        participantes_con_examenes=participantes_con_examenes,
        examenes=examenes,
        datos_participantes=datos_participantes
    )


###
### Eventos Abiertos - Virtual Asincrónico
###
@app.route('/tablero/eventos/abiertos')
@app.route('/tablero/eventos/abiertos/page/<int:page>')
@login_required
def listar_eventos_abiertos(page=1):
    
    # Filtrar eventos con modalidad Virtual asincrónica
    eventos_query = {
        "modalidad": "Virtual asincrónica"
    }
    
    # Paginación
    eventos_por_pagina = 20
    total_eventos = collection_eventos.count_documents(eventos_query)
    total_paginas = (total_eventos + eventos_por_pagina - 1) // eventos_por_pagina
    
    # Obtener eventos para la página actual
    eventos_cursor = collection_eventos.find(eventos_query).sort("fecha_inicio", -1).skip((page - 1) * eventos_por_pagina).limit(eventos_por_pagina)
    eventos = list(eventos_cursor)
    
    # Añadir información adicional para cada evento
    for evento in eventos:
        codigo_evento = evento["codigo"]
        
        # Verificar si el usuario es organizador
        es_organizador = collection_participantes.find_one({
            "codigo_evento": codigo_evento,
            "cedula": str(current_user.cedula),
            "rol": "coorganizador"
        }) is not None
        evento["es_organizador"] = es_organizador
        
        # Contar participantes
        evento["total_participantes"] = collection_participantes.count_documents({
            "codigo_evento": codigo_evento,
            "rol": "participante"
        })
        
        # Contar contenidos LMS
        evento["total_contenidos"] = collection_eva.count_documents({
            "codigo_evento": codigo_evento
        })
        
        # Contar exámenes
        evento["total_examenes"] = collection_eva.count_documents({
            "codigo_evento": codigo_evento,
            "tipo": "examen"
        })
        
        # Verificar si tiene contenidos LMS
        evento["tiene_lms"] = evento["total_contenidos"] > 0
    
    return render_template(
        'eventos_abiertos.html',
        active_section='eventos',
        page=page,
        total_paginas=total_paginas,
        total_eventos=total_eventos,
        eventos=eventos,
    )


###
### Política de privacidad y protección de datos personales
###
@app.route('/politica-privacidad', methods=['GET'])
def politica_privacidad():
    return render_template('politica_privacidad.html')


###
### Nosotros
###
@app.route('/nosotros')
def nosotros():
    # Obtener los datos del jefe y subjefe desde la base de datos
    jefe = collection_usuarios.find_one({"jefe": True}, {"nombres": 1, "apellidos": 1, "foto": 1, "cargo": 1})
    subjefe = collection_usuarios.find_one({"subjefe": True}, {"nombres": 1, "apellidos": 1, "foto": 1, "cargo": 1})

    denadoi_users = list(collection_usuarios.find(
        {"rol": "denadoi", "jefe": {"$ne": True}, "subjefe": {"$ne": True}},
        {"nombres": 1, "apellidos": 1, "foto": 1, "cargo": 1}
    ))

    # Construir las URLs de las fotos o usar una imagen predeterminada
    jefe_foto_url = f"/static/usuarios/{jefe['foto']}" if jefe and jefe.get('foto') else "/static/assets/user-avatar.png"
    subjefe_foto_url = f"/static/usuarios/{subjefe['foto']}" if subjefe and subjefe.get('foto') else "/static/assets/user-avatar.png"

    # Generar URLs de fotos para los usuarios "denadoi"
    for usuario in denadoi_users:
        usuario["foto_url"] = f"/static/usuarios/{usuario['foto']}" if usuario.get("foto") else "/static/assets/user-avatar.png"

    return render_template('nosotros.html',
        jefe=jefe,
        subjefe=subjefe,
        jefe_foto_url=jefe_foto_url,
        subjefe_foto_url=subjefe_foto_url,
        denadoi_users=denadoi_users,
    )


###
### LMS
###
def zfill_filter(value, width=2):
    return str(value).zfill(width)
app.jinja_env.filters['zfill'] = zfill_filter


###
### Repositorio de archivos de evento
###
from werkzeug.utils import secure_filename
import os

### Extensiones permitidas para archivos del repositorio
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'pdf', 'ppt', 'pptx', 'doc', 'docx'}


import os
import uuid
from flask import request, render_template, redirect, url_for, abort, flash
from werkzeug.utils import secure_filename
@app.route('/tablero/eventos/<codigo_evento>/repositorio', methods=['GET', 'POST'])
@login_required
def subir_archivo(codigo_evento):
    evento = collection_eventos.find_one({'codigo': codigo_evento})
    if not evento:
        abort(404)

    carpeta_evento = os.path.join(app.config['UPLOAD_FOLDER'], codigo_evento)
    os.makedirs(carpeta_evento, exist_ok=True)

    if request.method == 'POST':
        archivo = request.files.get('archivo')
        titulo = request.form.get('titulo', '')
        autor = request.form.get('autor', '')

        if archivo and archivo.filename:
            filename = secure_filename(archivo.filename)
            ext = filename.rsplit('.', 1)[1].lower()

            nombre_unico = f"{uuid.uuid4()}.{ext}"

            ruta_guardado = os.path.join(carpeta_evento, nombre_unico)
            archivo.save(ruta_guardado)

            ultimo_archivo = collection_repositorio.find_one(
                {'codigo_evento': codigo_evento},
                sort=[('orden', -1)]
            )
            nuevo_orden = 1 if not ultimo_archivo else ultimo_archivo['orden'] + 1

            nombre_descarga = f"{codigo_evento}_{nuevo_orden}.{ext}"

            collection_repositorio.insert_one({
                'codigo_evento': codigo_evento,
                'titulo': titulo,
                'autor': autor,
                'nombre': nombre_unico,
                'nombre_descarga': nombre_descarga,
                'orden': nuevo_orden
            })

            flash('Archivo subido correctamente.', 'success')
            return redirect(url_for('subir_archivo', codigo_evento=codigo_evento))
        else:
            flash('No se seleccionó ningún archivo.', 'danger')

    # Obtener lista de archivos para mostrar plantilla
    archivos = list(collection_repositorio.find({'codigo_evento': codigo_evento}).sort('orden', 1))

    return render_template('subir_archivo.html', evento=evento, archivos=archivos, generar_url_descarga=generar_url_descarga)


@app.route('/eliminar_archivo/<codigo_evento>/<nombre>', methods=['POST'])
@login_required  # Asegura que solo usuarios autenticados puedan eliminar archivos
def eliminar_archivo(codigo_evento, nombre):
    # Verificar que el archivo exista en la base de datos
    archivo = collection_repositorio.find_one({
        'codigo_evento': codigo_evento,
        'nombre': nombre
    })
    
    if not archivo:
        flash('El archivo no existe.', 'danger')
        return redirect(url_for('subir_archivo', codigo_evento=codigo_evento))
    
    # Verificar que el archivo exista en el sistema de archivos
    carpeta_evento = os.path.join(app.config['UPLOAD_FOLDER'], codigo_evento)
    ruta_archivo = os.path.join(carpeta_evento, nombre)
    
    try:
        # Eliminar el archivo del sistema de archivos si existe
        if os.path.isfile(ruta_archivo):
            os.remove(ruta_archivo)
        
        # Eliminar el registro de la base de datos
        collection_repositorio.delete_one({
            'codigo_evento': codigo_evento,
            'nombre': nombre
        })
        
        flash('Archivo eliminado correctamente.', 'success')
    except Exception as e:
        flash(f'Error al eliminar el archivo: {str(e)}', 'danger')
    
    return redirect(url_for('subir_archivo', codigo_evento=codigo_evento))


import hashlib
import time
from flask import send_from_directory, abort, request
def generar_firma(codigo_evento, nombre, expires):
    datos = f"{codigo_evento}:{nombre}:{expires}:{app.config['SECRET_KEY']}"
    return hashlib.sha256(datos.encode()).hexdigest()


@app.route('/descargar_archivo/<codigo_evento>/<nombre>')
def descargar_archivo(codigo_evento, nombre):
    expires = request.args.get('expires')
    signature = request.args.get('signature')

    if not all([expires, signature]):
        abort(403)

    if int(expires) < int(time.time()):
        abort(403)

    firma_esperada = generar_firma(codigo_evento, nombre, expires)
    if signature != firma_esperada:
        abort(403)

    carpeta_evento = os.path.join(app.config['UPLOAD_FOLDER'], codigo_evento)
    ruta_archivo = os.path.join(carpeta_evento, nombre)

    if not os.path.isfile(ruta_archivo):
        abort(404)

    archivo_db = collection_repositorio.find_one({
        'codigo_evento': codigo_evento,
        'nombre': nombre
    })
    
    nombre_descarga = archivo_db.get('nombre_descarga', nombre) if archivo_db else nombre

    return send_from_directory(
        carpeta_evento,
        nombre,
        as_attachment=True,
        download_name=nombre_descarga
    )


def generar_url_descarga(codigo_evento, nombre, tiempo_expiracion_minutos=5):
    expires = int(time.time()) + tiempo_expiracion_minutos * 60
    signature = generar_firma(codigo_evento, nombre, str(expires))

    return url_for('descargar_archivo', codigo_evento=codigo_evento, nombre=nombre, expires=expires, signature=signature, _external=True)


###
### Repositorio
###
from app.auth import token_required
@app.route('/repositorio/<codigo_evento>', methods=['GET'])
@token_required
def repositorio(codigo_evento):
    # Verificamos que exista el evento con ese código
    evento = collection_eventos.find_one({'codigo': codigo_evento})
    if not evento:
        abort(404)
    
    # Obtener los archivos del evento ordenados
    archivos = list(collection_repositorio.find({'codigo_evento': codigo_evento}).sort('orden', 1))
    
    # Generar URLs de descarga para cada archivo
    for archivo in archivos:
        archivo['url_descarga'] = generar_url_descarga(
            codigo_evento, 
            archivo['nombre']
        )
    
    return render_template('repositorio.html', 
                          evento=evento,
                          archivos=archivos,
                          generar_url_descarga=generar_url_descarga)


###
### Encuesta de satisfacción
###
@app.route('/encuesta/<codigo_evento>', methods=['GET', 'POST'])
def encuesta_satisfaccion(codigo_evento):
    # Verificar si el evento existe
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        abort(404)

    # Verificar si la encuesta está disponible
    ahora = datetime.now()
    fecha_inicio = evento.get('fecha_inicio')
    fecha_fin = evento.get('fecha_fin') + timedelta(days=2)  # Añadir 2 días a la fecha de fin

    # Convertir fechas a datetime si son strings
    if isinstance(fecha_inicio, str):
        fecha_inicio = datetime.strptime(fecha_inicio, '%Y-%m-%d %H:%M:%S')
    if isinstance(fecha_fin, str):
        fecha_fin = datetime.strptime(fecha_fin, '%Y-%m-%d %H:%M:%S')

    # Verificar si estamos dentro del período permitido
    encuesta_disponible = fecha_inicio <= ahora <= fecha_fin

    if request.method == 'POST' and not encuesta_disponible:
        flash('La encuesta no está disponible en este momento.', 'error')
        return redirect(url_for('resumen_evento', codigo_evento=codigo_evento))

    if request.method == 'POST':
        # Verificar si es spam
        if request.form.get('email'):  # Si el campo oculto de email está lleno, es spam
            flash('¡Gracias por completar la encuesta!', 'success')
            return redirect(url_for('encuesta_satisfaccion', codigo_evento=codigo_evento))

        # Verificar tiempo de llenado
        timestamp_inicio = request.form.get('timestamp_inicio')
        if timestamp_inicio:
            tiempo_transcurrido = (datetime.now().timestamp() * 1000 - float(timestamp_inicio)) / 1000
            if tiempo_transcurrido < 10:  # Menos de 10 segundos
                flash('¡Gracias por completar la encuesta!', 'success')
                return redirect(url_for('encuesta_satisfaccion', codigo_evento=codigo_evento))

        # Validar que todos los campos requeridos estén presentes
        campos_requeridos = {
            'D1': ['Masculino', 'Femenino'],
            'D2': ['20–30', '31–40', '41–50', '51–60', '61+'],
            'D3': [
                'medico_general_ce',
                'medico_general_urg',
                'medico_especialista',
                'odontologo',
                'odontologo_especialista',
                'enfermero',
                'tecnico_enfermeria',
                'laboratorista',
                'tecnico_laboratorio',
                'fisioterapeuta',
                'farmaceutico',
                'fonoaudiologo',
                'psicologo',
                'nutricionista',
                'trabajador_social',
                'estudiante_salud',
                'administrativo',
                'otro'
            ],
            'D4': ['1', '2', '3', '4'],
            'D5': ['<5', '5–10', '11–20', '21–30', '31–40', '+40'],
            'A1': ['1', '2', '3', '4', '5'],
            'A2': ['1', '2', '3', '4', '5'],
            'A3': ['1', '2', '3', '4', '5'],
            'A4': ['1', '2', '3', '4', '5'],
            'A5': ['1', '2', '3', '4', '5'],
            'A6': ['1', '2', '3', '4', '5'],
            'A7': ['1', '2', '3', '4', '5'],
            'B1': ['1', '2', '3', '4', '5'],
            'B2': ['1', '2', '3', '4', '5'],
            'B3': ['1', '2', '3', '4', '5'],
            'B4': ['1', '2', '3', '4', '5'],
            'B5': ['1', '2', '3', '4', '5'],
            'B6': ['1', '2', '3', '4', '5'],
            'B7': ['1', '2', '3', '4', '5'],
            'N1': ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10'],
            'N2': ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10']
        }

        respuestas = {}
        errores = []

        # Validar respuestas
        for codigo, valores_permitidos in campos_requeridos.items():
            valor = request.form.get(codigo)
            if not valor:
                errores.append(f'Falta la respuesta para {codigo}')
            elif valor not in valores_permitidos:
                errores.append(f'Respuesta inválida para {codigo}')
            else:
                respuestas[codigo] = valor

        # Validar comentarios (opcionales)
        respuestas['C1'] = request.form.get('C1', '')
        respuestas['C2'] = request.form.get('C2', '')
        respuestas['C3'] = request.form.get('C3', '')

        if errores:
            for error in errores:
                flash(error, 'error')
            return redirect(url_for('encuesta_satisfaccion', codigo_evento=codigo_evento))

        # Guardar la respuesta en la base de datos
        collection_encuestas.insert_one({
            'codigo_evento': codigo_evento,
            'respuestas': respuestas,
            'fecha': datetime.now()
        })

        flash('¡Gracias por completar la encuesta!', 'success')
        return redirect(url_for('encuesta_satisfaccion', codigo_evento=codigo_evento))

    return render_template('encuesta.html', evento=evento, encuesta_disponible=encuesta_disponible)


###
### Cierre de evento
###
@app.route('/cierre/<codigo_evento>', methods=['GET'])
def cierre_evento(codigo_evento):
    # Buscar el evento en la base de datos
    evento = collection_eventos.find_one({'codigo': codigo_evento})
    
    if not evento:
        flash('Evento no encontrado', 'error')
        return redirect(url_for('home'))
    
    # Generar el código QR para la encuesta
    url_encuesta = url_for('encuesta_satisfaccion', codigo_evento=codigo_evento, _external=True)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(url_encuesta)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Guardar el QR en un buffer
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    # Obtener el afiche del evento
    afiche_path = os.path.join(app.config['UPLOAD_FOLDER'], evento.get('afiche', 'default.png'))
    if not os.path.exists(afiche_path):
        afiche_path = os.path.join(app.config['UPLOAD_FOLDER'], 'default.png')
    
    # Obtener el estado del evento
    estado = calcular_estado(evento['fecha_inicio'])
    
    return render_template('cierre.html', 
                         evento=evento,
                         qr_base64=qr_base64,
                         url_encuesta=url_encuesta,
                         afiche_path=afiche_path,
                         estado=estado)


@app.route('/tablero/metricas/<codigo_evento>/exportar_csv')
@login_required
def exportar_encuesta_csv(codigo_evento):
    # Obtener las respuestas de la encuesta para el evento
    respuestas = list(collection_encuestas.find({'codigo_evento': codigo_evento}))
    
    if not respuestas:
        flash('No hay respuestas de encuesta disponibles para este evento.', 'error')
        return redirect(url_for('resumen_evento', codigo_evento=codigo_evento))
    
    # Crear el archivo CSV en memoria
    output = StringIO()
    writer = csv.writer(output)
    
    # Escribir encabezados
    headers = [
        'Fecha', 'Hora', 'D1', 'D2', 'D3', 'D4', 'D5',
        'A1', 'A2', 'A3', 'A4', 'A5', 'A6', 'A7',
        'B1', 'B2', 'B3', 'B4', 'B5', 'B6', 'B7',
        'N1', 'N2',
        'C1', 'C2', 'C3'
    ]
    writer.writerow(headers)
    
    # Escribir datos
    for respuesta in respuestas:
        # Obtener fecha y hora por separado
        fecha_hora = respuesta.get('fecha', datetime.now())
        if isinstance(fecha_hora, str):
            fecha_hora = datetime.strptime(fecha_hora, '%Y-%m-%d %H:%M:%S')
        fecha = fecha_hora.strftime('%Y-%m-%d')
        hora = fecha_hora.strftime('%H:%M:%S')
        
        # Obtener los datos de las respuestas
        respuestas_data = respuesta.get('respuestas', {})
        
        row = [
            fecha,
            hora,
            respuestas_data.get('D1', ''),
            respuestas_data.get('D2', ''),
            respuestas_data.get('D3', ''),
            respuestas_data.get('D4', ''),
            respuestas_data.get('D5', ''),
            respuestas_data.get('A1', ''),
            respuestas_data.get('A2', ''),
            respuestas_data.get('A3', ''),
            respuestas_data.get('A4', ''),
            respuestas_data.get('A5', ''),
            respuestas_data.get('A6', ''),
            respuestas_data.get('A7', ''),
            respuestas_data.get('B1', ''),
            respuestas_data.get('B2', ''),
            respuestas_data.get('B3', ''),
            respuestas_data.get('B4', ''),
            respuestas_data.get('B5', ''),
            respuestas_data.get('B6', ''),
            respuestas_data.get('B7', ''),
            respuestas_data.get('N1', ''),
            respuestas_data.get('N2', ''),
            respuestas_data.get('C1', ''),
            respuestas_data.get('C2', ''),
            respuestas_data.get('C3', '')
        ]
        writer.writerow(row)
    
    # Preparar la respuesta
    output.seek(0)
    return Response(
        output.getvalue().encode('utf-8'),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment;filename=encuesta_{codigo_evento}.csv",
            "Content-Type": "text/csv; charset=utf-8"
        }
    )


@app.route('/tablero/metricas/<codigo_evento>/informe')
@login_required
def informe_avanzado(codigo_evento):
    # Obtener el evento
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    if not evento:
        flash('Evento no encontrado', 'error')
        return redirect(url_for('home'))

    # Obtener el total de participantes
    total_participantes = collection_participantes.count_documents({
        "codigo_evento": codigo_evento,
        "rol": "participante"
    })

    # Obtener todos los participantes del evento para generar gráfica de perfil
    participantes = list(collection_participantes.find({
        "codigo_evento": codigo_evento,
        "rol": "participante"
    }))

    # Generar gráfica de perfil profesional
    grafica_perfil = generar_grafica_perfil(participantes, evento.get('nombre', 'Evento'))
    
    # Generar gráfica de regiones
    grafica_region = generar_grafica_region(participantes, evento.get('nombre', 'Evento'))

    # Obtener las respuestas de la encuesta
    respuestas = list(collection_encuestas.find({'codigo_evento': codigo_evento}))
    
    # Procesar los datos para las métricas
    total_respuestas = len(respuestas)
    
    # Calcular promedios por sección
    promedios = {
        'A': {'total': 0, 'count': 0},  # Plataforma CertiCSS
        'B': {'total': 0, 'count': 0},  # Evento Académico
        'N': {'total': 0, 'count': 0}   # Satisfacción global
    }

    # Contadores para datos demográficos
    demograficos = {
        'D1': {'Masculino': 0, 'Femenino': 0},
        'D2': {'20–30': 0, '31–40': 0, '41–50': 0, '51–60': 0, '61+': 0},
        'D3': {},  # Perfiles profesionales
        'D4': {'1': 0, '2': 0, '3': 0, '4': 0},
        'D5': {'<5': 0, '5–10': 0, '11–20': 0, '21–30': 0, '31–40': 0, '+40': 0}
    }

    # Procesar cada respuesta solo si existen
    if respuestas:
        for respuesta in respuestas:
            respuestas_data = respuesta.get('respuestas', {})
            
            # Calcular promedios de secciones A, B y N
            for seccion in ['A', 'B']:
                for i in range(1, 8):  # A1-A7 y B1-B7
                    key = f'{seccion}{i}'
                    if key in respuestas_data:
                        valor = int(respuestas_data[key])
                        promedios[seccion]['total'] += valor
                        promedios[seccion]['count'] += 1

            # Calcular promedio de sección N
            for i in range(1, 3):  # N1 y N2
                key = f'N{i}'
                if key in respuestas_data:
                    valor = int(respuestas_data[key])
                    promedios['N']['total'] += valor
                    promedios['N']['count'] += 1

            # Contar datos demográficos
            for key in demograficos:
                if key in respuestas_data:
                    valor = respuestas_data[key]
                    if key == 'D3':  # Perfiles profesionales
                        demograficos[key][valor] = demograficos[key].get(valor, 0) + 1
                    else:
                        demograficos[key][valor] = demograficos[key].get(valor, 0) + 1

    # Calcular promedios finales
    metricas = {
        'total_respuestas': total_respuestas,
        'total_participantes': total_participantes,
        'promedio_plataforma': round(promedios['A']['total'] / promedios['A']['count'], 2) if promedios['A']['count'] > 0 else 0,
        'promedio_evento': round(promedios['B']['total'] / promedios['B']['count'], 2) if promedios['B']['count'] > 0 else 0,
        'promedio_satisfaccion': round(promedios['N']['total'] / promedios['N']['count'], 2) if promedios['N']['count'] > 0 else 0,
        'demograficos': demograficos
    }

    # Generar gráfica de araña
    grafica_spider = generar_grafica_spider(respuestas, evento.get('nombre', 'Evento'))

    # Generar gráficas demográficas específicas
    grafica_demografia_sexo = generar_grafica_demografia_sexo(metricas['demograficos']['D1'], evento.get('nombre', 'Evento'))
    grafica_demografia_grupoetario = generar_grafica_demografia_grupoetario(metricas['demograficos']['D2'], evento.get('nombre', 'Evento'))

    # Calcular Alfa de Cronbach
    alfa_cronbach = calcular_alfa_cronbach(respuestas)

    # Calcular Net Promoter Score (NPS)
    nps = calcular_nps(respuestas)

    # Calcular Net Promoter Score (NPS) CertiCSS
    nps_certicss = calcular_nps_certicss()

    return render_template('metrica_avanzada.html', 
        evento=evento,
        metricas=metricas,
        grafica_perfil=grafica_perfil,
        grafica_region=grafica_region,
        grafica_spider=grafica_spider,
        grafica_demografia_sexo=grafica_demografia_sexo,
        grafica_demografia_grupoetario=grafica_demografia_grupoetario,
        alfa_cronbach=alfa_cronbach,
        nps=nps,
        nps_certicss=nps_certicss)


def calcular_alfa_cronbach(respuestas):
    """
    Calcula el Alfa de Cronbach global del instrumento para las preguntas B1 a B7
    utilizando todas las encuestas de satisfacción disponibles en toda la plataforma.
    
    Args:
        respuestas (list): Lista de diccionarios con las respuestas de la encuesta del evento actual.
                           Este parámetro se mantiene por compatibilidad pero no se usa.
    
    Returns:
        float: El valor del Alfa de Cronbach global de toda la plataforma, o None si no hay suficientes datos.
    """
    # Obtener todas las encuestas de toda la plataforma
    todas_encuestas = list(collection_encuestas.find({}))
    
    if not todas_encuestas:
        return None

    # Extraer solo la parte de 'respuestas' de cada documento
    respuestas_data_list = [r.get('respuestas', {}) for r in todas_encuestas]
    df = pd.DataFrame(respuestas_data_list)

    # Definir las columnas de interés para el cálculo del Alfa de Cronbach
    items_b = [f'B{i}' for i in range(1, 8)]  # B1, B2, B3, B4, B5, B6, B7

    # Verificar que las columnas existan en el DataFrame
    if not all(col in df.columns for col in items_b):
        return None

    # Filtrar el DataFrame para incluir solo las columnas B1-B7
    df_items = df[items_b]

    # Convertir las columnas a numéricas, forzando errores a NaN
    for col in items_b:
        df_items[col] = pd.to_numeric(df_items[col], errors='coerce')

    # Eliminar filas con valores nulos en cualquiera de los ítems B
    df_items.dropna(inplace=True)

    # Si no quedan datos después de eliminar nulos, no se puede calcular
    if df_items.empty or len(df_items.columns) < 2:
        return None

    k = len(items_b)  # Número de ítems (siempre 7 para B1-B7)

    # Varianza de cada ítem
    variances_item = df_items.var(axis=0, ddof=1)  # ddof=1 para varianza muestral
    sum_variances_item = variances_item.sum()

    # Varianza de la suma total de los ítems
    total_score = df_items.sum(axis=1)
    variance_total_score = total_score.var(ddof=1)  # ddof=1 para varianza muestral

    # Evitar división por cero si la varianza total es 0 (todos los encuestados respondieron igual)
    if variance_total_score == 0:
        return 1.0  # Si todos responden igual, la consistencia es perfecta

    # Calcular Alfa de Cronbach
    alpha = (k / (k - 1)) * (1 - (sum_variances_item / variance_total_score))

    return round(alpha, 2)  # Redondear a 2 decimales para presentación


def calcular_nps(respuestas):
    """
    Calcula el Net Promoter Score (NPS) basado en la pregunta N1.

    Args:
        respuestas (list): Lista de diccionarios con las respuestas de la encuesta.
                           Cada diccionario debe contener una clave 'respuestas'
                           con la clave N1 (escala 0-10).

    Returns:
        float: El valor del NPS (entre -100 y 100), o None si no hay suficientes datos.
    """
    if not respuestas:
        return None

    promoters = 0
    passives = 0
    detractors = 0
    total_valid_responses = 0

    for respuesta in respuestas:
        respuestas_data = respuesta.get('respuestas', {})
        n1_value_str = respuestas_data.get('N1')
        
        if n1_value_str is not None:
            try:
                n1_value = int(n1_value_str)
                if 0 <= n1_value <= 10: # Asegurarse de que el valor esté en el rango esperado
                    total_valid_responses += 1
                    if n1_value >= 9:
                        promoters += 1
                    elif n1_value >= 7:
                        passives += 1
                    else: # 0-6
                        detractors += 1
            except ValueError:
                # Ignorar valores que no se pueden convertir a int
                pass

    if total_valid_responses == 0:
        return None # No hay respuestas válidas para calcular el NPS

    # Calcular porcentajes
    percent_promoters = (promoters / total_valid_responses) * 100
    percent_detractors = (detractors / total_valid_responses) * 100

    nps_score = percent_promoters - percent_detractors
    return round(nps_score, 2) # Redondear a 2 decimales para presentación


def calcular_nps_certicss():
    """
    Calcula el Net Promoter Score (NPS) global utilizando todas las encuestas
    de satisfacción disponibles en toda la plataforma.

    Returns:
        float: El valor del NPS global (entre -100 y 100), o None si no hay suficientes datos.
    """
    # Obtener todas las encuestas de toda la plataforma
    todas_encuestas = list(collection_encuestas.find({}))
    
    if not todas_encuestas:
        return None

    promoters = 0
    passives = 0
    detractors = 0
    total_valid_responses = 0

    for respuesta in todas_encuestas: # Iterar sobre TODAS las encuestas
        respuestas_data = respuesta.get('respuestas', {})
        n1_value_str = respuestas_data.get('N1')
        
        if n1_value_str is not None:
            try:
                n1_value = int(n1_value_str)
                if 0 <= n1_value <= 10: # Asegurarse de que el valor esté en el rango esperado
                    total_valid_responses += 1
                    if n1_value >= 9:
                        promoters += 1
                    elif n1_value >= 7:
                        passives += 1
                    else: # 0-6
                        detractors += 1
            except ValueError:
                # Ignorar valores que no se pueden convertir a int
                pass

    if total_valid_responses == 0:
        return None # No hay respuestas válidas para calcular el NPS global

    # Calcular porcentajes
    percent_promoters = (promoters / total_valid_responses) * 100
    percent_detractors = (detractors / total_valid_responses) * 100

    nps_score = percent_promoters - percent_detractors
    return round(nps_score, 2) # Redondear a 2 decimales para presentación


def generar_grafica_perfil(participantes, evento_nombre):
    """
    Genera una gráfica de barras con la distribución de participantes por perfil profesional
    """
    # Mapeo de códigos de perfil a nombres legibles
    PERFILES_MAP = {
        "medico_general": "Médico General - Consulta Externa",
        "medico_urgencias": "Médico General - Urgencias", 
        "medico_especialista": "Médico Especialista",
        "medico_residente": "Médico Residente",
        "medico_interno": "Médico Interno",
        "odontologo": "Odontólogo",
        "odontologo_especialista": "Odontólogo Especialista",
        "enfermero": "Enfermero(a)",
        "tecnico_enfermeria": "Técnico Enfermería",
        "laboratorista": "Laboratorista",
        "tecnico_laboratorio": "Técnico Laboratorio",
        "farmaceutico": "Farmacéutico(a)",
        "tecnico_farmacia": "Técnico Farmacia",
        "reges": "Estadístico de Salud",
        "fisioterapeuta": "Fisioterapeuta",
        "fonoaudiologo": "Fonoaudiólogo(a)",
        "psicologo": "Psicólogo(a)",
        "nutricionista": "Nutricionista",
        "estudiante_salud": "Estudiante",
        "administrativo": "Administrativo",
        "otro": "Otro"
    }
    
    # Contar participantes por perfil
    perfiles_count = {}
    for participante in participantes:
        perfil = participante.get('perfil', 'otro')
        perfiles_count[perfil] = perfiles_count.get(perfil, 0) + 1
    
    # Si no hay datos, retornar None
    if not perfiles_count:
        return None
    
    # Crear la figura
    plt.figure(figsize=(12, 6))
    
    # Ordenar por frecuencia descendente
    perfiles_ordenados = sorted(perfiles_count.items(), key=lambda x: x[1], reverse=True)

    # Extraer datos ordenados
    labels = [PERFILES_MAP.get(perfil, perfil.title()) for perfil, _ in perfiles_ordenados]
    values = [count for _, count in perfiles_ordenados]
    
    # Crear gráfica de barras
    bars = plt.bar(labels, values, color='#0058A6', alpha=0.8)
    
    # Personalizar la gráfica
    plt.title(f'Distribución de Participantes por Perfil Profesional', 
          fontsize=10, fontweight='bold', pad=20)

    # Subtítulo: por ejemplo, fecha o lugar
    plt.text(0.5, 1.15, evento_nombre, 
            ha='center', va='bottom', transform=plt.gca().transAxes,
            fontsize=12, style='italic')
    
    plt.xlabel('Perfil Profesional de Participantes', fontsize=10, fontweight='bold')
    plt.ylabel('Número de Participantes', fontsize=10, fontweight='bold')
    
    # Rotar etiquetas del eje X para mejor legibilidad
    plt.xticks(rotation=20, ha='right')
    
    # Agregar valores en las barras
    for bar, value in zip(bars, values):
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                f'{value}', ha='center', va='bottom', fontweight='bold')
    
    # Ajustar layout
    plt.tight_layout()
    
    # Convertir la gráfica a imagen base64
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png', dpi=300, bbox_inches='tight')
    img_buffer.seek(0)
    img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
    plt.close()
    
    return f"data:image/png;base64,{img_base64}"


def generar_grafica_region(participantes, evento_nombre):
    """
    Genera una gráfica de barras con la distribución de participantes por región/provincia
    """
    # Mapeo de códigos de región a nombres legibles
    REGION_MAP = {
        "panama": "Panamá Metro",
        "sanmiguelito": "San Miguelito",
        "panamaoeste": "Panamá Oeste",
        "panamaeste": "Panamá Este",
        "bocasdeltoro": "Bocas del Toro",
        "cocle": "Coclé",
        "colon": "Colón",
        "chiriqui": "Chiriquí",
        "herrera": "Herrera",
        "lossantos": "Los Santos",
        "veraguas": "Veraguas"
    }
    
    # Contar participantes por región
    regiones_count = {}
    for participante in participantes:
        region = participante.get('region', 'otro')
        regiones_count[region] = regiones_count.get(region, 0) + 1
    
    # Si no hay datos, retornar None
    if not regiones_count:
        return None
    
    # Crear la figura
    plt.figure(figsize=(12, 6))
    
    # Ordenar por frecuencia descendente
    regiones_ordenadas = sorted(regiones_count.items(), key=lambda x: x[1], reverse=True)

    # Preparar datos ordenados
    labels = [REGION_MAP.get(region, region.title()) for region, _ in regiones_ordenadas]
    values = [count for _, count in regiones_ordenadas]
    
    # Crear gráfica de barras
    bars = plt.bar(labels, values, color='#10B981', alpha=0.8)  # Color verde para diferenciar
    
    # Personalizar la gráfica
    plt.title(f'Distribución de Participantes por Región/Provincia', 
           fontsize=10, fontweight='bold', pad=20)

    # Subtítulo: por ejemplo, fecha o lugar
    plt.text(0.5, 1.15, evento_nombre, 
            ha='center', va='bottom', transform=plt.gca().transAxes,
            fontsize=12, style='italic')
    
    plt.xlabel('Región/Provincia de Procedencia', fontsize=10, fontweight='bold')
    plt.ylabel('Número de Participantes', fontsize=10, fontweight='bold')
    
    # Rotar etiquetas del eje X para mejor legibilidad
    plt.xticks(rotation=20, ha='right')
    
    # Agregar valores en las barras
    for bar, value in zip(bars, values):
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                f'{value}', ha='center', va='bottom', fontweight='bold')
    
    # Ajustar layout
    plt.tight_layout()
    
    # Convertir la gráfica a imagen base64
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png', dpi=300, bbox_inches='tight')
    img_buffer.seek(0)
    img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
    plt.close()
    
    return f"data:image/png;base64,{img_base64}"


def generar_grafica_spider(respuestas, evento_nombre):
    """
    Genera una gráfica radial (de araña) con la evaluación del evento académico
    basada en los promedios de las respuestas.
    """
    if not respuestas:
        return None # No hay datos para generar la gráfica

    # Convertir las respuestas a un DataFrame de Pandas para facilitar el procesamiento
    # Extraer solo la parte de 'respuestas' de cada documento
    respuestas_data_list = [r.get('respuestas', {}) for r in respuestas]
    df = pd.DataFrame(respuestas_data_list)

    # Limpieza de datos: asegurar que las columnas B1-B7 sean numéricas
    # y manejar valores no válidos (NaN)
    for col in ['B1', 'B2', 'B3', 'B4', 'B5', 'B6', 'B7']:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
        else:
            df[col] = np.nan # Si la columna no existe, llenarla con NaN

    # Eliminar filas que tengan NaN en las columnas B relevantes para los cálculos
    df.dropna(subset=['B1', 'B2', 'B3', 'B4', 'B5', 'B6', 'B7'], inplace=True)

    if df.empty:
        return None # No hay datos válidos después de la limpieza

    # Calcular los promedios para los ejes del gráfico de araña

    # pertinencia y aplicabilidad -> B1
    pert_aplic = df['B1'].mean()

    # claridad y coherencia -> promedio B2 B4
    clar_coh = df[['B2', 'B4']].mean(axis=1).mean()

    # actualización -> B2
    actualiz = df['B2'].mean()

    # calidad de ponencias -> promedio B3 B4
    cal_pon = df[['B3', 'B4']].mean(axis=1).mean()

    # organización -> promedio B5 B6 B7
    organiz = df[['B5', 'B6', 'B7']].mean(axis=1).mean()

    # Nombres de las categorías (ejes)
    categories = [
        f'Pertinencia y Aplicabilidad\n({pert_aplic:.1f})',
        f'Claridad y Coherencia\n({clar_coh:.1f})',
        f'Actualización Científica\n({actualiz:.1f})',
        f'Calidad de Ponencias\n({cal_pon:.1f})',
        f'Organización y Logística\n({organiz:.1f})'
    ]

    # Valores de los promedios
    values = [pert_aplic, clar_coh, actualiz, cal_pon, organiz]
    
    # Filtrar valores NaN que puedan resultar de promedios de columnas vacías
    # Si algún valor es NaN, el gráfico no se generará correctamente.
    # Si hay un NaN, se convierte a 0 o manejaremos el error.
    values = [0 if pd.isna(v) else v for v in values] # Reemplazar NaN con 0 para evitar errores de plot

    # Número de variables
    num_vars = len(categories)

    # Calcular el ángulo para cada eje
    angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()
    # Para cerrar el círculo en el gráfico de araña, el primer punto se repite al final
    values = values + values[:1]
    angles = angles + angles[:1]

    # Crear la figura y los ejes polares
    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))

    # Trazar la línea del gráfico de araña
    ax.plot(angles, values, color='#0058A6', linewidth=2, linestyle='solid', label='Promedio General')
    ax.fill(angles, values, color='#0058A6', alpha=0.25)

    # Configurar los ejes
    ax.set_theta_offset(np.pi / 2) # Rotar para que el primer eje esté arriba
    ax.set_theta_direction(-1) # Sentido horario

    # Etiquetas de los ejes
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, fontsize=10, fontweight='bold', wrap=True)

    # Rango del eje radial (escala Likert de 1 a 5)
    ax.set_ylim(1, 5)
    ax.set_yticks(np.arange(1, 6)) # Mostrar ticks en 1, 2, 3, 4, 5
    ax.set_yticklabels([f'{i}' for i in np.arange(1, 6)], color="gray", size=8)
    ax.tick_params(axis='y', pad=10) # Ajustar el padding de los ticks del eje Y

    # Título y subtítulo
    ax.set_title(f'Evaluación del Evento Académico', 
                 fontsize=14, fontweight='bold', pad=20)
    
    plt.text(0.5, 1.2, evento_nombre, 
             horizontalalignment='center', verticalalignment='center', 
             transform=ax.transAxes, fontsize=12, style='italic')

    # Leyenda
    ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1))

    # Ajustar layout
    plt.tight_layout()

    # Convertir la gráfica a imagen base64
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png', dpi=300, bbox_inches='tight')
    img_buffer.seek(0)
    img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
    plt.close(fig) # Cierra la figura para liberar memoria
    
    return f"data:image/png;base64,{img_base64}"


def generar_grafica_demografia_sexo(sexo_data, evento_nombre):
    """
    Genera una gráfica de barras con la distribución por Sexo.
    """
    if not sexo_data or all(v == 0 for v in sexo_data.values()):
        return None

    title = 'Distribución por Sexo'
    labels_map = {'Masculino': 'Masculino', 'Femenino': 'Femenino'}

    # Obtener datos y mapear etiquetas
    data_counts = {k: sexo_data.get(k, 0) for k in labels_map.keys()}
    
    # Filtrar categorías con 0 conteo para no mostrarlas si no hay datos
    valid_labels = [labels_map[k] for k, v in data_counts.items() if v > 0]
    valid_values = [v for k, v in data_counts.items() if v > 0]

    if not valid_values: # Si no hay datos válidos, retornar None
        return None

    fig, ax = plt.subplots(figsize=(7, 5)) # Ajustar tamaño para un solo gráfico

    # Definir colores: celeste para masculino, rosado para femenino
    color_map = {'Masculino': '#4FC3F7', 'Femenino': '#F06292'}
    bar_colors = [color_map.get(label, '#BDBDBD') for label in valid_labels]

    bars = ax.bar(valid_labels, valid_values, color=bar_colors, alpha=0.8)
    
    # Personalizar el subplot
    ax.set_title(title, fontsize=10, fontweight='bold', pad=20)
    # Subtítulo con el nombre del evento en cursiva
    plt.text(0.5, 1.15, evento_nombre, ha='center', va='bottom', transform=ax.transAxes, fontsize=12, style='italic')
    ax.set_ylabel('Número de encuestados', fontsize=10)
    
    ax.tick_params(axis='x', rotation=0, labelsize=9) # No rotar si son pocas categorías
    ax.tick_params(axis='y', labelsize=9)

    # Agregar valores en las barras
    for bar, value in zip(bars, valid_values):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                f'{value}', ha='center', va='bottom', fontweight='bold', fontsize=8)
    
    plt.tight_layout(rect=[0, 0, 1, 0.95]) # Ajustar rect para dejar espacio al subtítulo

    # Convertir la gráfica a imagen base64
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png', dpi=300, bbox_inches='tight')
    img_buffer.seek(0)
    img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
    plt.close(fig) # Cierra la figura para liberar memoria
    
    return f"data:image/png;base64,{img_base64}"


def generar_grafica_demografia_grupoetario(edad_data, evento_nombre):
    """
    Genera una gráfica de barras con la distribución por Grupo Etario.
    """
    if not edad_data or all(v == 0 for v in edad_data.values()):
        return None

    title = 'Distribución por Grupo Etario'
    # Mapeo para aceptar ambos tipos de guion
    labels_map = {
        '20–30': '20-30', '20-30': '20-30',
        '31–40': '31-40', '31-40': '31-40',
        '41–50': '41-50', '41-50': '41-50',
        '51–60': '51-60', '51-60': '51-60',
        '61+': '61+'
    }

    # Asegurar el orden de las categorías de edad
    ordered_keys = ['20-30', '31-40', '41-50', '51-60', '61+']

    # Sumar los valores de ambas variantes de cada grupo
    data_counts = {}
    for k in ordered_keys:
        suma = 0
        for key, label in labels_map.items():
            if label == k:
                suma += edad_data.get(key, 0)
        data_counts[k] = suma

    # Filtrar categorías con 0 conteo para no mostrarlas si no hay datos
    valid_labels = [k for k, v in data_counts.items() if v > 0]
    valid_values = [v for k, v in data_counts.items() if v > 0]

    if not valid_values: # Si no hay datos válidos, retornar None
        return None

    fig, ax = plt.subplots(figsize=(7, 5)) # Ajustar tamaño para un solo gráfico

    bars = ax.bar(valid_labels, valid_values, color='#8e24aa', alpha=0.8)

    # Personalizar el subplot
    ax.set_title(title, fontsize=10, fontweight='bold', pad=20)
    # Subtítulo con el nombre del evento en cursiva
    plt.text(0.5, 1.15, evento_nombre, ha='center', va='bottom', transform=ax.transAxes, fontsize=12, style='italic')
    ax.set_ylabel('Número de encuestados', fontsize=10)

    # Use ax.set_xticklabels for horizontal alignment
    ax.tick_params(axis='x', rotation=30, labelsize=9) 
    ax.tick_params(axis='y', labelsize=9)
    ax.set_xticklabels(valid_labels, rotation=30, ha='right', fontsize=9)

    # Agregar valores en las barras
    for bar, value in zip(bars, valid_values):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                f'{value}', ha='center', va='bottom', fontweight='bold', fontsize=8)

    plt.tight_layout(rect=[0, 0, 1, 0.95]) # Ajustar rect para dejar espacio al subtítulo

    # Convertir la gráfica a imagen base64
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png', dpi=300, bbox_inches='tight')
    img_buffer.seek(0)
    img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
    plt.close(fig) # Cierra la figura para liberar memoria

    return f"data:image/png;base64,{img_base64}"


###
### Etiqueta filtro de fecha
###
from datetime import date

def calcular_estado(fecha):
    hoy = date.today()
    # Convertir fecha a date si es datetime
    if isinstance(fecha, datetime):
        fecha = fecha.date()
    if fecha == hoy:
        return Markup('<span class="inline-flex items-center gap-1.5 py-1 px-2 rounded-lg text-xs font-medium bg-red-100 text-red-800">En curso</span>')
    elif fecha < hoy:
        return Markup('<span class="inline-flex items-center gap-1.5 py-1 px-2 rounded-lg text-xs font-medium bg-green-100 text-green-800">Finalizado</span>')
    else:
        return ""

app.jinja_env.filters['estado'] = calcular_estado


###
### generación de certificado
###
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.pdfgen import canvas
from reportlab.pdfbase.pdfmetrics import stringWidth
from pdfrw import PdfReader, PdfWriter, PageMerge
import os

def generar_pdf_participante(participante, afiche_path):
    codigo_evento = participante['codigo_evento']
    evento = collection_eventos.find_one({"codigo": codigo_evento})

    titulo_evento = evento.get('nombre', 'Título no disponible')
    unidad_evento = evento.get('unidad_ejecutora', 'Unidad ejecutora no disponible')
    carga_horaria_evento = evento.get('carga_horaria', '08')
    fecha_fin_evento = evento.get('fecha_fin')
    fecha_fin_formateada = fecha_fin_evento.strftime('%d de %B de %Y')

    fecha_inicio_evento = evento.get('fecha_inicio')
    fecha_inicio_formateada = fecha_inicio_evento.strftime('%d')

    fecha_evento = evento.get('fecha_fin', 'Fecha no disponible')

    # Definir la ruta donde se guardará el PDF
    pdf_directory = 'static/certificados/'

    if not os.path.exists(pdf_directory):
        os.makedirs(pdf_directory)

    # Nombre del archivo PDF temporal a crear
    temp_pdf_filename = f"temp_{participante['nanoid']}.pdf"
    temp_pdf_path = os.path.join(pdf_directory, temp_pdf_filename)

    c = canvas.Canvas(temp_pdf_path, pagesize=landscape(letter))

    c.setFont("Helvetica", 14)
    #c.setFillColor("black")
    c.setFillColor(HexColor('#002060'))

    page_width = landscape(letter)[0]

    # Escribir los datos del participante centrados en la página
    def draw_centered_text(y_position, text, font="Helvetica", size=12):
        c.setFont(font, size)  # Cambiar fuente y tamaño
        text_width = c.stringWidth(text, font, size)
        x_position = (page_width - text_width) / 2  # Calcular posición X para centrar
        c.drawString(x_position, y_position, text)

    draw_centered_text(6 * inch, f"{unidad_evento}", font='Helvetica-Bold', size=15)
    draw_centered_text(5.7 * inch, f"confiere el presente certificado a:")
    draw_centered_text(5.2 * inch, f"{participante['nombres']} {participante['apellidos']}", font="Helvetica-Bold", size=18)
    draw_centered_text(4.8 * inch, f"Cédula: {participante['cedula']}", font="Helvetica-Oblique", size=14)
    draw_centered_text(4.4 * inch, f"Por su asistencia en calidad de {participante['rol']} en:")
    draw_centered_text(4 * inch, f"{titulo_evento}", font="Helvetica-Bold", size=14)

    if participante['rol'] == 'ponente':
        draw_centered_text(3.5 * inch, f"Con la ponencia:")
        draw_centered_text(3.2 * inch, f"{participante.get('titulo_ponencia', 'N/A')}", font="Helvetica-Bold", size=16)
    else:
        draw_centered_text(3.5 * inch, f"Actividad académica con una duración de {carga_horaria_evento} horas")
        draw_centered_text(3.2 * inch, f"{fecha_inicio_formateada + ' al ' + fecha_fin_formateada if fecha_inicio_evento != fecha_fin_evento else fecha_fin_formateada}")

    draw_centered_text(2.7 * inch, f"Dado en la República de Panamá, Provincia de Panamá, el {fecha_fin_formateada}")

    # Código de certificado en la esquina superior derecha
    c.setFillColor("white")
    c.setFont("Courier", 12)
    nanoid_text = f"ID validación: {participante['nanoid']}"
    text_width = c.stringWidth(nanoid_text, "Courier", 12)
    x_position = page_width - text_width - 0.3 * inch
    c.drawString(x_position, landscape(letter)[1] - 0.3 * inch, nanoid_text)

    # Generar el código QR
    qr_data = participante['nanoid']
    qr_img_path = "static/certificados/qrcode.png"  # Ruta donde se guardará el QR
    qr_img = qrcode.make(qr_data)
    qr_img.save(qr_img_path)

    # Insertar el código QR en el PDF justo debajo del nanoid
    c.drawImage(qr_img_path, x_position - -1.45 * inch, landscape(letter)[1] - 1.5 * inch, width=1 * inch, height=1 * inch)  # Ajusta tamaño y posición según sea necesario

    # Finalizar el nuevo PDF
    c.save()

    os.remove(qr_img_path)

    # Nombre del archivo PDF combinado a crear
    output_pdf_filename = f"{participante['nanoid']}.pdf"
    output_pdf_path = os.path.join(pdf_directory, output_pdf_filename)

    # Leer el PDF de fondo
    background_pdf = PdfReader(afiche_path)
    new_pdf = PdfReader(temp_pdf_path)

    writer = PdfWriter()

    # Combinar las páginas
    for page in range(len(background_pdf.pages)):
        background_page = background_pdf.pages[page]
        new_page = new_pdf.pages[0] if page < len(new_pdf.pages) else None

        if new_page:
            # Combinar la página de fondo con la nueva página
            PageMerge(background_page).add(new_page).render()

        writer.addPage(background_page)

    # Guardar el PDF combinado en la ruta deseada
    writer.write(output_pdf_path)

    # Eliminar el archivo PDF temporal
    os.remove(temp_pdf_path)

    return output_pdf_path  # Retornar la ruta del archivo guardado


###
###
###
@app.route('/certificado/<nanoid>', methods=['GET'])
def generar_pdf(nanoid):
    # Buscar el participante en la base de datos usando el nanoid
    participante = collection_participantes.find_one({"nanoid": nanoid})

    if not participante:
        abort(404)  # Si no se encuentra el participante

    # Obtener el código del evento para buscar plantilla *** aun no funciona
    codigo_evento = participante['codigo_evento']
    evento = collection_eventos.find_one({"codigo": codigo_evento})

    # if not evento or not evento.get('afiche'):
    #     abort(404)  # Si no se encuentra el evento o no hay afiche

    ##afiche_path = f"static/assets/plantilla-certificado.pdf"
    afiche_path = evento.get('certificado')

    # Si no se ha subido el certificado del evento, devuelve error 404
    if not afiche_path:
        abort(404)

    # Llamar a la función para generar el PDF
    pdf_file = generar_pdf_participante(participante, afiche_path)

    return send_file(pdf_file)  # Enviar el archivo PDF al cliente para descarga


###
### Generación de constancia de asistencia
###
from io import BytesIO
from flask import send_file
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.pdfgen import canvas
from pdfrw import PdfReader, PdfWriter, PageMerge
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate

def generar_constancia_asistencia(participante, afiche_path):
    # Crear un buffer en memoria para el PDF
    buffer = BytesIO()

    # Crear el PDF en memoria
    c = canvas.Canvas(buffer, pagesize=letter)

    # Obtener datos del evento y participante
    codigo_evento = participante['codigo_evento']
    evento = collection_eventos.find_one({"codigo": codigo_evento})

    titulo_evento = evento.get('nombre', 'Título no disponible')
    unidad_evento = evento.get('unidad_ejecutora', 'Unidad ejecutora no disponible')
    modalidad_evento = evento.get('modalidad', 'Modalidad no disponible')
    carga_horaria_evento = evento.get('carga_horaria', '08')
    ue_evento = evento.get('unidad_ejecutora', 'Unidad ejecutora no disponible')

    fi_evento = evento.get('fecha_inicio')
    if isinstance(fi_evento, str):
        fi_evento = datetime.strptime(fi_evento, '%Y-%m-%d %H:%M:%S')
    # Formatear la fecha
    fi_formateada = fi_evento.strftime('%d de %B de %Y')
    fid_formateada = fi_evento.strftime('%d')

    ff_evento = evento.get('fecha_fin')
    if isinstance(ff_evento, str):
        ff_evento = datetime.strptime(ff_evento, '%Y-%m-%d %H:%M:%S')
    # Formatear la fecha
    ff_formateada = ff_evento.strftime('%d de %B de %Y')

    # fecha_inicio = datetime.strptime(fi_evento, '%Y-%m-%d')
    # fecha_fin = datetime.strptime(ff_evento, '%Y-%m-%d')

    # Configurar fuentes y colores
    c.setFont("Helvetica", 14)
    c.setFillColor(HexColor('#002060'))  # Color azul oscuro

    page_width = letter[0]  # Ancho de la página
    page_height = letter[1]  # Alto de la página

    # Función para centrar texto
    def draw_centered_text(y_position, text, font="Helvetica", size=12):
        c.setFont(font, size)
        text_width = c.stringWidth(text, font, size)
        x_position = (page_width - text_width) / 2
        c.drawString(x_position, y_position, text)

    # Texto de la constancia
    draw_centered_text(8.5 * inch, "CAJA DE SEGURO SOCIAL", font='Helvetica-Bold', size=16)
    draw_centered_text(8.2 * inch, "DIRECCIÓN EJECUTIVA NACIONAL DE SERVICIOS Y PRESTACIONES EN SALUD", size=14)
    draw_centered_text(7.9 * inch, "DEPARTAMENTO NACIONAL DE DOCENCIA E INVESTIGACIÓN", size=14)
    # draw_centered_text(7.6 * inch, f"{unidad_evento.upper()}", size=14)
    draw_centered_text(7.0 * inch, "CONSTANCIA DE ASISTENCIA", font='Helvetica-Bold', size=18)

    # Configurar estilos para los párrafos
    styles = getSampleStyleSheet()
    style = styles['BodyText']
    style.fontSize = 12                     # Tamaño fuente
    style.leading = 24                      # Interlineado
    style.textColor = HexColor('#002060')   # Color de fuente

    # Texto de la constancia
    texto_constancia = (
        f"Se certifica la asistencia de <b>{participante['nombres']} {participante['apellidos']}</b>, "
        f"con cédula <b>{participante['cedula']}</b>, "
    )

    # Verificar si el participante tiene múltiples registros
    registros_participante = list(collection_participantes.find({
        "cedula": participante['cedula'],
        "codigo_evento": codigo_evento,
        "rol": "participante"
    }))

    if len(registros_participante) > 1:
        # Si tiene múltiples registros, mostrar los días específicos
        dias_asistencia = []
        for registro in registros_participante:
            if registro.get('indice_registro'):
                fecha = datetime.strptime(registro['indice_registro'], '%Y%m%d')
                dias_asistencia.append(fecha.strftime('%d de %B de %Y'))
        
        texto_constancia += f"participando los días {', '.join(dias_asistencia)}, "

    texto_constancia += (
        f"en el evento <b>'{titulo_evento}'</b>, realizado en modalidad "
        f"<b>{modalidad_evento.lower()}</b> y organizado por la unidad ejecutora <b>'{ue_evento}'</b>, "
        f"{'los días ' + fid_formateada + ' al ' + ff_formateada if fi_evento != ff_evento else 'el día ' + ff_formateada} con una duración de {carga_horaria_evento} horas académicas."
    )

    # Crear un párrafo
    constancia_paragraph = Paragraph(texto_constancia, style)

    # Texto de validación digital
    texto_validacion = (
        "La presente constancia es de carácter digital y puede validarse utilizando el código único suministrado: "
        f"<b>{participante['nanoid']}</b> en la plataforma CertiCSS del Departamento Nacional de Docencia e Investigación: <u>www.docenciamedica.org</u>."
    )

    # Crear otro párrafo
    validacion_paragraph = Paragraph(texto_validacion, style)

    # Texto de cumplimiento normativo
    texto_reglamento = (
        "Sirva la presente para cumplir con lo establecido en el Reglamento Interno de nuestra institución."
    )

    # Crear un tercer párrafo
    reglamento_paragraph = Paragraph(texto_reglamento, style)

    # Crear un elemento Flowable para el PDF
    story = [
        constancia_paragraph,
        validacion_paragraph,
        reglamento_paragraph
    ]

    # Configurar el PDF para usar los párrafos
    # Sin embargo, para mantener el control sobre la posición, no usaremos SimpleDocTemplate directamente.
    # En su lugar, dibujaremos los párrafos manualmente en el canvas.

    # Dibujar los párrafos manualmente
    from reportlab.platypus import FrameBreak, Frame
    frame = Frame(1 * inch, 6.5 * inch, 7 * inch, 2 * inch, showBoundary=0)  # Ajusta las dimensiones según sea necesario

    # Agregar los párrafos al frame
    # Sin embargo, para mantener el control total, usaremos canvas para dibujar los párrafos en posiciones específicas.

    # Posicionar manualmente los párrafos
    margin_left = 1.25 * inch  # Margen izquierdo
    y_position = 6.5 * inch  # Posición Y inicial

    # Dibujar los párrafos en el canvas
    for paragraph in story:
        w, h = paragraph.wrapOn(c, 6 * inch, 2 * inch)  # Ajusta el ancho según sea necesario
        paragraph.drawOn(c, margin_left, y_position - h)
        y_position -= h + 0.2 * inch  # Espacio entre párrafos

    # Finalizar el PDF
    c.save()

    # Leer el PDF de fondo (plantilla)
    background_pdf = PdfReader(afiche_path)
    buffer.seek(0)
    new_pdf = PdfReader(buffer)

    # Combinar el PDF generado con la plantilla
    writer = PdfWriter()
    for page in range(len(background_pdf.pages)):
        background_page = background_pdf.pages[page]
        new_page = new_pdf.pages[0] if page < len(new_pdf.pages) else None

        if new_page:
            PageMerge(background_page).add(new_page).render()

        writer.addPage(background_page)

    # Guardar el PDF combinado en un buffer en memoria
    output_buffer = BytesIO()
    writer.write(output_buffer)
    output_buffer.seek(0)

    return output_buffer


@app.route('/constancia/<nanoid>', methods=['GET'])
def descargar_constancia(nanoid):
    # Buscar el participante en la base de datos usando el nanoid
    participante = collection_participantes.find_one({"nanoid": nanoid})

    if not participante:
        abort(404)  # Si no se encuentra el participante

    # Ruta de la plantilla de la constancia
    afiche_path = "static/assets/membrete-css-generico.pdf"

    # Llamar a la función para generar el PDF en memoria
    pdf_buffer = generar_constancia_asistencia(participante, afiche_path)

    # Enviar el PDF al cliente para descarga
    return send_file(pdf_buffer, as_attachment=True, download_name=f"constancia_{participante['nanoid']}.pdf", mimetype='application/pdf')


###
### Sistema de logs
###
import logging
from logging.handlers import RotatingFileHandler

# Crear la carpeta /logs si no existe
if not os.path.exists('logs'):
    os.makedirs('logs')

# Nombre del archivo de log basado en la fecha actual
log_filename = datetime.now().strftime('logs/app-%Y-%m-%d.log')

# Configuración del logging
logger = logging.getLogger('app_logger')
logger.setLevel(logging.INFO)  # Nivel de logging (INFO, WARNING, ERROR, etc.)

# Formato del log
formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Manejador para rotar archivos cada 250 registros
handler = RotatingFileHandler(
    log_filename,  # Nombre del archivo de log
    maxBytes=0,  # No usar tamaño máximo (usamos backupCount en su lugar)
    backupCount=250,  # Número máximo de registros por archivo
)
handler.setFormatter(formatter)
logger.addHandler(handler)

def log_event(message):
    client_ip = get_client_ip()  # Obtener la dirección IP del cliente
    log_message = f"{message} {client_ip}."
    logger.info(log_message)


###
### Obtener IP
###
from flask import request
def get_client_ip():
    """
    Obtiene la dirección IP del cliente.
    """
    if request.headers.get('X-Forwarded-For'):
        # Si la aplicación está detrás de un proxy
        return request.headers.get('X-Forwarded-For').split(',')[0]
    else:
        # Si no hay proxy, usar la IP directa
        return request.remote_addr


###
### Importaciones de appy blueprints
###

### Logs
from app.logs import logs_blueprint
app.register_blueprint(logs_blueprint)

### Herramientas
from app.herramientas import herramientas_bp
app.register_blueprint(herramientas_bp)

### Asistencia dinámica
from app.asistencia import asistencia_bp
app.register_blueprint(asistencia_bp)

### Exportar eventos
from app.exportar import exportar_bp
app.register_blueprint(exportar_bp)

### Importar eventos
from app.importar import importar_bp
app.register_blueprint(importar_bp)

### Plataforma LMS
from app.plataforma import plataforma_bp
app.register_blueprint(plataforma_bp)

### Plataforma LMS auth
from app.auth import auth_bp
app.register_blueprint(auth_bp)

### Búsqueda avanzada y normalizador
from app.normalizador import normalizador_bp
app.register_blueprint(normalizador_bp)

### Búsqueda avanzada y normalizador
from app.regiones import regiones_bp
app.register_blueprint(regiones_bp)

### Catálogo de eventos
from app.catalogo import catalogo_bp
app.register_blueprint(catalogo_bp)

### Acerca de
from app.creditos import creditos_bp
app.register_blueprint(creditos_bp)

### Importaciones para gráficas
import matplotlib
matplotlib.use('Agg')  # Configurar matplotlib para usar backend no interactivo
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.figure import Figure
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
import numpy as np
import pandas as pd
import io
import base64

###
### robots.txt
###
@app.route("/robots.txt")
def robots():
    return send_from_directory(app.static_folder, "robots.txt")


###
### Errores
###
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(401)
def unauthorized_error(e):
    return render_template('401.html'), 401

@app.errorhandler(403)
def forbidden_error(e):
    return render_template('403.html'), 403


if __name__ == '__main__':
    app.run(host=app.config['HOST'], port=app.config['PORT'])
