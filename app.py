from flask import Flask, jsonify, request, render_template, redirect, url_for, flash
from flask_login import LoginManager, login_user, UserMixin, logout_user, login_required
from pymongo import MongoClient
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from PIL import Image
from markupsafe import Markup
import os
import random
import string
import hashlib

app = Flask(__name__)


###
### Salt key 
###
app.config['SECRET_KEY'] = os.urandom(24)  # Genera una clave secreta aleatoria
#app.config['BASE_URL'] = "http://localhost:5000/"       # base url del sitio local
app.config['BASE_URL'] = "https://docenciamedica.org/"  # base url demo

###
### Variable para BASE_URL disponible globalmente 
###
@app.context_processor
def inject_base_url():
    return dict(BASE_URL=app.config['BASE_URL'])


###
### Salt key para producción
###
# app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'default_secret_key')
# export FLASK_SECRET_KEY='mi_clave_secreta_super_segura' // hacer esto antes de iniciar el script y eliminar esta línea


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


##
## Conexión a MongoDB local
##
# client = MongoClient('mongodb://localhost:27017/')
# db = client['certi_css']
# collection_eventos = db['eventos']
# collection_participantes = db['participantes']
# collection_usuarios = db['usuarios']


###
### Conexión a MongoDB docker
###
mongo_uri = os.getenv("MONGO_URI", "mongodb://db:27017/")
client = MongoClient(mongo_uri)
db = client['certi_css']
collection_eventos = db['eventos']
collection_participantes = db['participantes']
collection_usuarios = db['usuarios']


###
### Crear índice único para evitar duplicados
###
try:
    collection_participantes.create_index([("cedula", 1), ("codigo_evento", 1), ("titulo_ponencia", 1)], unique=True)
except Exception as e:
    print(f"Error al crear índice: {e}")


###
### Gestión de imágenes
###
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limitar a 16 MB

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


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
            'timestamp': timestamp
        })
        flash('Registro exitoso. Ahora puedes iniciar sesión.')
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
        
        if user_data and check_password_hash(user_data['password'], password):
            user = User(
                email=user_data['email'], 
                password=user_data['password'], 
                rol=user_data['rol'], 
                nombres=user_data['nombres']
            )
            user.id = str(user_data['_id'])
            login_user(user)
            return redirect(url_for('tablero_coordinadores'))
        
        flash('Credenciales incorrectas. Inténtalo de nuevo.')

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
        }

        # Solo actualizar la contraseña si se proporciona
        if password:
            updated_user_data["password"] = generate_password_hash(password)  # Asegúrate de importar y usar esta función

        # Actualizar el usuario en la base de datos
        collection_usuarios.update_one({"_id": ObjectId(user_id)}, {"$set": updated_user_data})

        flash('Usuario actualizado con éxito.')
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
###
###
@app.route('/eliminar_usuario/<user_id>', methods=['POST'])
@login_required
def eliminar_usuario(user_id):
    # Lógica para eliminar un usuario
    collection_usuarios.delete_one({"_id": ObjectId(user_id)})
    flash('Usuario eliminado con éxito.')
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
    # Obtener la fecha y hora actual
    ahora = datetime.utcnow()
    
    # Consultar eventos futuros
    eventos_futuros = collection_eventos.find({"fecha_inicio": {"$gte": ahora}}).sort("fecha_inicio").limit(6)

    return render_template('home.html', eventos=eventos_futuros)


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
        return redirect(url_for('page_not_found'))  # Redirigir a la página 404 si el código no existe
    
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
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    return render_template('participantes.html', 
        participantes=participantes,
        total_participantes=total_participantes,
        evento=evento,
        nombre_evento=evento['nombre']
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
        flash("Evento creado con éxito", "success")
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
        
        flash("Evento actualizado con éxito", "success")
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
        return "No se puede eliminar el evento porque tiene participantes asociados.", 400
    
    # Si no hay participantes, eliminar el evento
    collection_eventos.delete_one({"codigo": codigo_evento})
    return redirect(url_for('listar_eventos'))  # Redirigir a la lista de eventos


###
### Eliminar participante
###
@app.route('/eliminar_participante/<nanoid>', methods=['POST'])
@login_required
def eliminar_participante(nanoid):
    participante = collection_participantes.find_one({"nanoid": nanoid})
    result = collection_participantes.delete_one({"nanoid": nanoid})
    return redirect(url_for('listar_participantes', codigo_evento=participante['codigo_evento']))

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
        #url = f"http://localhost:5000/registrar_participante/{codigo_evento}"
        url = f"https://docenciamedica.org/registrar_participante/{codigo_evento}"
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
### local
###
# if __name__ == '__main__':
#     app.run(debug=True)

###
### Contenedor
###
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)