from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, session, abort
from flask_login import LoginManager, login_user, UserMixin, logout_user, current_user, login_required
from pymongo import MongoClient
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from PIL import Image
from markupsafe import Markup
from config import config
import os
import random
import string
import hashlib

app = Flask(__name__)


###
### Configuraciones comunes
###
app.config.from_object(config)                              # Cargar configuraciones desde config.py

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)     # Crear la carpeta de subida si no existe

client = MongoClient(app.config['MONGO_URI'])               # Configurar MongoDB usando la URI de la configuración
db = client['certi_css']
collection_eventos = db['eventos']
collection_participantes = db['participantes']
collection_usuarios = db['usuarios']

@app.context_processor                                      # Variable BASE_URL
def inject_base_url():
    return dict(BASE_URL=app.config['BASE_URL'])


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
            nombres=user_data['nombres']
        )
        user.id = str(user_data['_id'])
        return user
    return None


class User(UserMixin):
    def __init__(self, email, password, rol, nombres):
        self.email = email
        self.password = password
        self.rol = rol
        self.nombres = nombres
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
    collection_participantes.create_index([("cedula", 1), ("codigo_evento", 1), ("titulo_ponencia", 1)], unique=True)
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
            'valid_until': datetime.now() + timedelta(minutes=1)
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
@app.route('/registrar-usuario', methods=['GET', 'POST'])
@login_required
def registro():
    if request.method == 'POST':
        nombres = request.form['nombres']
        apellidos = request.form['apellidos']
        genero = request.form['genero']
        cedula = request.form['cedula']
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
        flash('Registro exitoso. Ahora el usuario puede iniciar sesión.')
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
                    nombres=user_data['nombres']
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
@app.route('/usuarios')
@app.route('/usuarios/page/<int:page>')
@login_required
def listar_usuarios(page=1):
    usuarios_por_pagina = 20  # Número de usuarios por página

    # Contar el total de usuarios
    total_usuarios = collection_usuarios.count_documents({"rol": {"$ne": "administrador"}})  # Excluir administradores si es necesario
    # Calcular el número total de páginas
    total_paginas = (total_usuarios + usuarios_por_pagina - 1) // usuarios_por_pagina  # Redondear hacia arriba

    # Obtener los usuarios para la página actual
    usuarios_cursor = collection_usuarios.find({"rol": {"$ne": "administrador"}}).sort("fecha_registro", -1).skip((page - 1) * usuarios_por_pagina).limit(usuarios_por_pagina)
    usuarios = list(usuarios_cursor)

    return render_template('usuarios.html', 
        usuarios=usuarios, 
        page=page, 
        total_paginas=total_paginas,
        total_usuarios=total_usuarios
    )


###
###
###
@app.route('/editar_usuario/<user_id>', methods=['GET', 'POST'])
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
            "region": region,
            "phone": phone,
            "unidad_ejecutora": unidad_ejecutora,
            "departamento": departamento,
            "rol": rol,
            "cargo": cargo,
            "jefe": jefe,
            "subjefe": subjefe,
        }

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
    return render_template('editar_usuario.html', usuario=usuario)


###
### Perfil de usuario
###
@app.route('/usuario/<user_id>')
@login_required
def mostrar_usuario(user_id):
    # Obtener los datos del usuario desde la base de datos usando el user_id
    usuario = collection_usuarios.find_one({"_id": ObjectId(user_id)})
    
    if not usuario:
        flash("Usuario no encontrado", "danger")
        return redirect(url_for('listar_usuarios'))  # Redirigir a la lista de usuarios si no se encuentra

    return render_template('perfil_usuario.html', usuario=usuario)


###
### Acciones de usuario
###
@app.route('/eliminar_usuario/<user_id>', methods=['POST'])
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


@app.route('/toggle_activo/<user_id>', methods=['POST'])
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

        # Actualizar el participante en la base de datos
        collection_participantes.update_one(
            {"nanoid": nanoid},
            {"$set": {
                "nombres": nombres,
                "apellidos": apellidos,
                "cedula": cedula
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
        titulo_ponencia = request.form.get('titulo_ponencia', '').strip()

        # Actualizar el participante en la base de datos
        collection_participantes.update_one(
            {"nanoid": nanoid},
            {"$set": {
                "nombres": nombres,
                "apellidos": apellidos,
                "cedula": cedula,
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
    for evento in eventos_prox:
        fecha_inicio = evento['fecha_inicio']
        if fecha_inicio.date() == ahora.date():
            evento['estado'] = 'En curso'
        elif fecha_inicio.date() < ahora.date():
            evento['estado'] = 'Finalizado'
        else:
            evento['estado'] = 'Publicado'
        eventos_prox_list_estado.append(evento)

    num_eventos = len(eventos_prox_list)

    usuarios_recientes = list(collection_usuarios.find({"rol": {"$ne": "administrador"}}).sort('fecha_registro', -1).limit(5))

    num_usuarios_recientes = len(usuarios_recientes)
    
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
        total_participantes=total_participantes
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

    # Verificar si el evento está cerrado
    if evento.get('estado_evento') == 'cerrado':
        return render_template('registrar.html', 
            evento_cerrado=True,
            nombre_evento=evento['nombre'],
            afiche_url=url_for('static', filename='uploads/' + evento['afiche_750'].split('/')[-1])
        )
    
    # Generar un nuevo OTP si no existe o ha expirado
    if codigo_evento not in otp_storage or datetime.now() >= otp_storage[codigo_evento]['valid_until']:
        otp_code = generate_otp()
        otp_storage[codigo_evento] = {
            'code': otp_code,
            'valid_until': datetime.now() + timedelta(minutes=1)
        }
    else:
        otp_code = otp_storage[codigo_evento]['code']

    return render_template('registrar.html', 
        otp=otp_code,
        evento=evento,
        codigo_evento=codigo_evento, 
        nombre_evento=evento['nombre'], 
        afiche_url=url_for('static', filename='uploads/' + evento['afiche_750'].split('/')[-1]),
        programa_url=evento.get('programa_url') 
    )


@app.route('/registrar', methods=['POST'])
def registrar():
    nombres = request.form['nombres']
    apellidos = request.form['apellidos']
    cedula = request.form['cedula']
    rol = request.form['rol']
    codigo_evento = request.form['codigo_evento']
    otp_ingresado = request.form['otp']
    timestamp = datetime.now()

    # Verificar si el participante ya está registrado en este evento
    if collection_participantes.find_one({"cedula": cedula, "codigo_evento": codigo_evento, "rol": "participante"}):
        flash("El participante ya está registrado en este evento.", "error")
        return redirect(url_for('registrar_participante', codigo_evento=codigo_evento))

    # Verificar si el código OTP existe y su validez
    if codigo_evento in otp_storage:
        otp_info = otp_storage[codigo_evento]
        
        # Validar si el registro se realizó durante la validez del OTP y si coincide con el OTP ingresado
        if datetime.now() <= otp_info['valid_until'] and otp_ingresado == otp_info['code']:
            # Generar nanoid
            nanoid = generate_nanoid(cedula, codigo_evento)
            
            # Insertar datos en la colección de MongoDB
            collection_participantes.insert_one({
                'nombres': nombres,
                'apellidos': apellidos,
                'cedula': cedula,
                'rol': rol,
                'codigo_evento': codigo_evento,
                'nanoid': nanoid,
                'timestamp': timestamp
            })

            # Mensaje de éxito o falla en registro
            flash("Registro exitoso. El certificado de participación se podrá descargar al finalizar el evento.", "success")

            return redirect(url_for('registrar_participante', codigo_evento=codigo_evento))
        else:
            flash("El OTP ha expirado o es incorrecto.", "error")
            return redirect(url_for('registrar_participante', codigo_evento=codigo_evento))
    else:
        flash("El código del evento no es válido.", "error")
        return redirect(url_for('registrar_participante', codigo_evento=codigo_evento))


###
### Redirección corta (solo registro de evento)
###
@app.route('/<codigo_evento>')
def redirigir_ruta_corta(codigo_evento):
    return redirect(url_for('registrar_participante', codigo_evento=codigo_evento))


###
### Formulario de registro de ponentes
###
@app.route('/registrar_ponente/<codigo_evento>', methods=['GET', 'POST'])
@login_required
def registrar_ponente(codigo_evento):
    evento = collection_eventos.find_one({"codigo": codigo_evento})

    # Verificar si el evento está cerrado
    if evento.get('estado_evento') == 'cerrado':
        return render_template('registrar_ponente.html', 
            evento_cerrado=True,
            nombre_evento=evento['nombre'],
            afiche_url=url_for('static', filename='uploads/' + evento['afiche_750'].split('/')[-1])
        )

    if request.method == 'POST':
        nombres = request.form['nombres']
        apellidos = request.form['apellidos']
        cedula = request.form['cedula']
        rol = request.form['rol']
        titulo_ponencia = request.form['titulo_ponencia']

        # Generar nanoid
        nanoid = generate_nanoid(cedula, codigo_evento, titulo_ponencia)

        # Insertar datos en la colección de MongoDB
        collection_participantes.insert_one({
            'nombres': nombres,
            'apellidos': apellidos,
            'cedula': cedula,
            'rol': rol,
            'titulo_ponencia': titulo_ponencia,
            'codigo_evento': codigo_evento,
            'nanoid': nanoid,
            'timestamp': datetime.now()  # Almacenar timestamp actual
        })

        flash("Ponente registrado con éxito.", "success")
        log_event(f"Usuario [{current_user.email}] registró al { rol } { cedula } en el evento { codigo_evento }.")
        return redirect(url_for('listar_participantes', codigo_evento=codigo_evento))

    return render_template('registrar_ponente.html',
        codigo_evento=codigo_evento,
        evento=evento,
        afiche_url=url_for('static', filename='uploads/' + evento['afiche_750'].split('/')[-1])
    )


###
### Listado de eventos próximos
###
@app.route('/eventos-proximos')
@app.route('/eventos-proximos/page/<int:page>')
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

    return render_template('eventos-proximos.html', 
        eventos=eventos, 
        page=page, 
        total_paginas=total_paginas,
        total_eventos=total_eventos
    )



###
### Listado de eventos anteriores
###
@app.route('/eventos-anteriores')
@app.route('/eventos-anteriores/page/<int:page>')
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

    return render_template('eventos-anteriores.html', 
        eventos=eventos, 
        page=page, 
        total_paginas=total_paginas,
        total_eventos=total_eventos
    )


###
### Todos los eventos
###
@app.route('/eventos')
@app.route('/eventos/page/<int:page>')
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

    return render_template('eventos.html',
        eventos=eventos,
        total_eventos=total_eventos,
        page=page,
        total_paginas=total_paginas
    )


###
### Listado de participantes de un evento
###
@app.route('/participantes/<codigo_evento>')
@login_required
def listar_participantes(codigo_evento):
    # Recuperar participantes registrados para el evento específico
    evento = collection_eventos.find_one({"codigo": codigo_evento})

    participantes_cursor = collection_participantes.find({"codigo_evento": codigo_evento})
    total_participantes = collection_participantes.count_documents({"codigo_evento": codigo_evento})
    participantes = list(participantes_cursor)
    
    estado_evento = evento.get('estado_evento', 'borrador')
    
    return render_template('participantes.html', 
        participantes=participantes,
        total_participantes=total_participantes,
        evento=evento,
        nombre_evento=evento['nombre'],
        estado_evento=estado_evento,
    )


###
### Formulario de creación de evento
###
@app.route('/evento-nuevo', methods=['GET', 'POST'])
@login_required
def crear_evento():
    if request.method == 'POST':
        nombre = request.form['nombre']
        unidad_ejecutora = request.form['unidad_ejecutora']
        lugar = request.form['lugar']
        tipo = request.form['tipo']
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
            'unidad_ejecutora': unidad_ejecutora,
            'lugar': lugar,
            'tipo': tipo,
            'modalidad': modalidad,
            'descripcion': descripcion,
            'fecha_inicio': fecha_inicio,
            'fecha_fin': fecha_fin,
            'estado_evento': estado_evento,
            'afiche': afiche_path if afiche_file else None,
            'afiche_750': resized_afiche_path if afiche_file else None,
            'fondo': fondo_path if fondo_file else None,
            'programa': programa_path if programa_file else None,
            'certificado': certificado_path if certificado_file else None,
            'timestamp': timestamp
        })
        log_event(f"Usuario [{current_user.email}] ha creado el evento {codigo} exitosamente.")
        return redirect(url_for('crear_evento'))  # Redirigir a la lista de eventos

    return render_template('crear_evento.html')


###
### Editar evento
###
@app.route('/editar_evento/<codigo_evento>', methods=['GET', 'POST'])
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
        unidad_ejecutora = request.form['unidad_ejecutora']
        lugar = request.form['lugar']
        tipo = request.form['tipo']
        modalidad = request.form['modalidad']
        descripcion = request.form['descripcion']

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
                'unidad_ejecutora': unidad_ejecutora,
                'lugar': lugar,
                'tipo': tipo,
                'modalidad': modalidad,
                'descripcion': descripcion,
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
        return redirect(url_for('crear_evento'))  # Redirigir a la lista de eventos

    return render_template('editar_evento.html', evento=evento)


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
@app.route('/cerrar_evento/<codigo_evento>', methods=['POST'])
@login_required
def cerrar_evento(codigo_evento):
    # Actualizar el estado del evento a "cerrado"
    collection_eventos.update_one(
        {"codigo": codigo_evento},
        {"$set": {"estado_evento": "cerrado"}}
    )
    log_event(f"Usuario [{current_user.email}] cerró el evento {codigo_evento}.")
    flash("Evento cerrado con éxito", "success")
    return redirect(url_for('listar_eventos'))  # Redirigir a la lista de eventos


###
### Validación para eliminar evento
###
@app.route('/eliminar_evento/<codigo_evento>', methods=['POST'])
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
###
###
@app.route('/buscar_certificados', methods=['GET', 'POST'])
def buscar_certificados():
    if request.method == 'POST':
        # Obtener el número de cédula del formulario
        cedula = request.form.get('cedula')
        
        # Buscar participantes por cédula
        participantes = list(collection_participantes.find({"cedula": cedula}))

        if not participantes:  # Si no hay participantes encontrados
            return render_template('lista_certificados.html', cedula=cedula, resultados=None)
        
        # Crear una lista para almacenar los resultados
        resultados = []
        
        for participante in participantes:
            codigo_evento = participante.get('codigo_evento')
            evento = collection_eventos.find_one({"codigo": codigo_evento})
            
            if evento:  # Verificar si el evento fue encontrado

                fecha_evento = evento.get('fecha_inicio', None)

                resultado = {
                    'nombres': participante['nombres'],
                    'apellidos': participante['apellidos'],
                    'cedula': participante['cedula'],
                    'nanoid': participante['nanoid'],
                    'rol': participante['rol'],
                    'codigo_evento': codigo_evento,
                    'titulo_evento': evento.get('nombre', 'Título no disponible'),
                    'fecha_evento': fecha_evento
                }
                resultados.append(resultado)
            else:
                # Manejar casos donde no se encuentra el evento
                resultado = {
                    'cedula': participante['cedula'],
                    'nanoid': participante['nanoid'],
                    'codigo_evento': codigo_evento,
                    'titulo_evento': 'Evento no encontrado',
                    'fecha_evento': None
                }
                resultados.append(resultado)

        return render_template('lista_certificados.html', resultados=resultados)  # Renderizar la plantilla con los resultados
    
    return render_template('buscar.html')  # Mostrar el formulario para buscar certificados


###
### Plantilla varias
###
@app.route('/plantillas')
def plantillas():
    return render_template('plantillas.html', active_section='plantillas')


###
### Política de privacidad y protección de datos personales
###
@app.route('/politica-privacidad', methods=['GET'])
def politica_privacidad():
    return render_template('politica_privacidad.html')


###
### Nosotros
###
@app.route('/nosotros', methods=['GET'])
def nosotros():
    return render_template('nosotros.html')


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
        draw_centered_text(3.5 * inch, f"Actividad académica con una duración de 08 horas")
        draw_centered_text(3.2 * inch, f"24 de enero de 2025")

    draw_centered_text(2.7 * inch, f"Dado en la República de Panamá, Provincia de Panamá, el 24 de enero de 2025")

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
    ue_evento = evento.get('unidad_ejecutora', 'Unidad ejecutora no disponible')
    
    fi_evento = evento.get('fecha_inicio')
    if isinstance(fi_evento, str):
        fi_evento = datetime.strptime(fi_evento, '%Y-%m-%d %H:%M:%S')
    # Formatear la fecha
    fi_formateada = fi_evento.strftime('%d de %B de %Y')
    
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
        f"con cédula <b>{participante['cedula']}</b>, en el evento <b>'{titulo_evento}'</b>, realizado en modalidad "
        f"<b>{modalidad_evento.lower()}</b> y organizado por la unidad ejecutora <b>'{ue_evento}'</b>, "
        f"el día <b>{fi_formateada}</b> en el horario de 7:00am a 3:00pm."
    )

    # Crear un párrafo
    constancia_paragraph = Paragraph(texto_constancia, style)

    # Texto de validación digital
    texto_validacion = (
        "La presente constancia es de carácter digital y puede validarse utilizando el código único suministrado: "
        f"<b>{participante['nanoid']}</b> en la plataforma CertiCSS del Departamento Nacional de Docencia e Investigación."
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
###
###
import os
from flask import Flask, render_template_string

def get_latest_log_file():
    log_dir = 'logs'
    log_files = [f for f in os.listdir(log_dir) if f.startswith('app-') and f.endswith('.log')]
    
    if not log_files:
        return None
    
    # Ordenar los archivos por fecha (el más reciente primero)
    log_files.sort(reverse=True)
    
    # Devolver la ruta completa del archivo más reciente
    return os.path.join(log_dir, log_files[0])

@app.route('/logs')
@login_required
def show_latest_log():
    latest_log_file = get_latest_log_file()
    
    if not latest_log_file:
        return "No hay archivos de registro de actividades."
    
    with open(latest_log_file, 'r') as file:
        log_content = file.read()
    
    return render_template('logs.html', log_file=latest_log_file, log_content=log_content)


@app.route('/descargar_log')
@login_required
def download_latest_log():
    latest_log_file = get_latest_log_file()
    
    if not latest_log_file:
        return "No hay archivos de registro de actividades."
    
    now = datetime.now()
    formatted_datetime = now.strftime("app-%Y-%m-%d-%H-%M-%S.log")
    
    return send_file(latest_log_file, as_attachment=True, download_name=formatted_datetime)


###
###
###
# Cargar la versión una sola vez al iniciar la aplicación
def load_version():
    try:
        with open("version.txt", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "Unknown"

VERSION = load_version()  # Variable global con la versión

@app.context_processor
def inject_version():
    return dict(version=VERSION)

    
if __name__ == '__main__':
    app.run(host=app.config['HOST'], port=app.config['PORT'])