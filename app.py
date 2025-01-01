from flask import Flask, request, render_template, redirect, url_for, flash
from flask_login import LoginManager, login_user, UserMixin, logout_user
from pymongo import MongoClient
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from PIL import Image
import os
import random
import string
import hashlib

app = Flask(__name__)


###
### Salt key 
###
app.config['SECRET_KEY'] = os.urandom(24)  # Genera una clave secreta aleatoria


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
    return collection_usuarios.find_one({"_id": user_id})


class User(UserMixin):
    def __init__(self, email, password, rol):
        self.email = email
        self.password = password
        self.rol = rol
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
## Conexión a MongoDB
##
client = MongoClient('mongodb://localhost:27017/')
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
@app.route('/registrar_usuario', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nombres = request.form['nombres']
        apellidos = request.form['apellidos']
        cedula = request.form['cedula']
        email = request.form['email']
        password = request.form['password']
        rol = request.form['rol']  # 'administrador' o 'coordinador'
        unidad_ejecutora = request.form['unidad_ejecutora']
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
            'cedula': cedula,
            "email": email,
            "password": hashed_password,
            "rol": rol,
            "unidad_ejecutora": unidad_ejecutora,
            'timestamp': timestamp
        })
        flash('Registro exitoso. Ahora puedes iniciar sesión.')
        return redirect(url_for('listar_usuarios'))

    return render_template('registrar_usuario.html')


###
### Login
###
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user_data = collection_usuarios.find_one({"email": email})
        
        if user_data and check_password_hash(user_data['password'], password):
            user = User(email=user_data['email'], password=user_data['password'], rol=user_data['rol'])
            user.id = str(user_data['_id'])
            login_user(user)
            flash('Inicio de sesión exitoso.')
            return redirect(url_for('home'))  # Redirigir a la página principal o donde necesites
        
        flash('Credenciales incorrectas. Inténtalo de nuevo.')

    return render_template('iniciar_sesion.html')


@app.route('/iniciar_sesion', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user_data = collection_usuarios.find_one({"email": email})
        
        if user_data and check_password_hash(user_data['password'], password):
            user = User(email=user_data['email'], password=user_data['password'], rol=user_data['rol'])
            user.id = str(user_data['_id'])
            login_user(user)
            flash('Inicio de sesión exitoso.')
            return redirect(url_for('home'))  # Redirigir a la página principal o donde necesites
        
        flash('Credenciales incorrectas. Inténtalo de nuevo.')

    return render_template('iniciar_sesion.html')


###
### Listado de usuarios
###
@app.route('/usuarios')
def listar_usuarios():
    usuarios = collection_usuarios.find()
    return render_template('usuarios.html', usuarios=usuarios)


###
###
###
@app.route('/editar_usuario/<user_id>', methods=['GET', 'POST'])
def editar_usuario(user_id):
    if request.method == 'POST':
        # Recoger los datos del formulario
        nombres = request.form.get('nombres')
        apellidos = request.form.get('apellidos')
        cedula = request.form.get('cedula')
        unidad_ejecutora = request.form.get('unidad_ejecutora')
        rol = request.form.get('rol')
        email = request.form.get('email')
        password = request.form.get('password')  # Si se permite cambiar la contraseña

        # Crear un diccionario con los nuevos datos
        updated_user_data = {
            "nombres": nombres,
            "apellidos": apellidos,
            "cedula": cedula,
            "unidad_ejecutora": unidad_ejecutora,
            "rol": rol,
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
###
###
@app.route('/eliminar_usuario/<user_id>', methods=['POST'])
def eliminar_usuario(user_id):
    # Lógica para eliminar un usuario
    collection_usuarios.delete_one({"_id": ObjectId(user_id)})
    flash('Usuario eliminado con éxito.')
    return redirect(url_for('listar_usuarios'))


###
###
###
@app.route('/salir', methods=['POST'])
def logout():
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
#@login_required
def tablero_coordinadores():

    eventos_proximos = collection_eventos.find({
        'fecha_inicio': {'$gte': datetime.now()}
    }).sort('fecha_inicio').limit(5)

    usuarios_recientes = collection_usuarios.find().sort('fecha_registro', -1).limit(5)
    
    return render_template('tablero.html', eventos=eventos_proximos, usuarios=usuarios_recientes)


###
### Formulario de registro de participantes
###
@app.route('/registrar_participante/<codigo_evento>')
def index(codigo_evento):
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

    return render_template('registrar.html', otp=otp_code, codigo_evento=codigo_evento, nombre_evento=evento['nombre'])


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
    if collection_participantes.find_one({"cedula": cedula, "codigo_evento": codigo_evento}):
        flash("El participante ya está registrado en este evento.", "error")
        return redirect(url_for('index', codigo_evento=codigo_evento))

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
            flash("Registro completado con éxito", "success")
            return redirect(url_for('index', codigo_evento=codigo_evento))
        else:
            flash("El OTP ha expirado o es incorrecto. Por favor, recargue la página.", "error")
            return redirect(url_for('index', codigo_evento=codigo_evento))
    else:
        flash("El código del evento no es válido.", "error")
        return redirect(url_for('index', codigo_evento=codigo_evento))


###
### Formulario de registro de ponentes
###
@app.route('/registrar_ponente/<codigo_evento>', methods=['GET', 'POST'])
def registrar_ponente(codigo_evento):
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

        flash("Ponente registrado con éxito", "success")
        return redirect(url_for('listar_participantes', codigo_evento=codigo_evento))

    return render_template('registrar_ponente.html', codigo_evento=codigo_evento)


###
### Listado de eventos próximos
###
@app.route('/eventos-proximos')
def listar_eventos_proximos():
    ahora = datetime.utcnow() 
    eventos_cursor = collection_eventos.find({"fecha_inicio": {"$gte": ahora}})  # Recuperar solo eventos futuros
    eventos = list(eventos_cursor)  # Convertir el cursor a una lista
    return render_template('eventos-proximos.html', eventos=eventos)


###
### Listado de eventos anteriores
###
@app.route('/eventos-anteriores')
def listar_eventos_anteriores():
    ahora = datetime.utcnow()
    eventos_cursor = collection_eventos.find({"fecha_inicio": {"$lt": ahora}})  # Recuperar solo eventos pasados
    eventos = list(eventos_cursor)  # Convertir el cursor a una lista
    return render_template('eventos-anteriores.html', eventos=eventos)


###
### Todos los eventos
###
@app.route('/eventos')
def listar_eventos():
    eventos_cursor = collection_eventos.find().sort("fecha_inicio", -1) ## -1 de reciente a antiguo / ## 1 de antiguo a reciente
    eventos = list(eventos_cursor) 
    return render_template('eventos.html', eventos=eventos)


###
### Listado de participantes de un evento
###
@app.route('/participantes/<codigo_evento>')
def listar_participantes(codigo_evento):
    # Recuperar participantes registrados para el evento específico
    participantes = collection_participantes.find({"codigo_evento": codigo_evento})
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    return render_template('participantes.html', participantes=participantes, codigo_evento=codigo_evento, nombre_evento=evento['nombre'])


###
### Formulario de creación de evento
###
@app.route('/crear_evento', methods=['GET', 'POST'])
def crear_evento():
    if request.method == 'POST':
        nombre = request.form['nombre']
        unidad_ejecutora = request.form['unidad_ejecutora']
        tipo = request.form['tipo']
        descripcion = request.form['descripcion']

        fecha_inicio_str = request.form['fecha_inicio']
        fecha_fin_str = request.form['fecha_fin']

        fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%d')
        fecha_fin = datetime.strptime(fecha_fin_str, '%Y-%m-%d')
       
        timestamp = request.form['timestamp']

        # Obtener un código único
        codigo = obtener_codigo_unico()

        # Carga de archivos
        afiche_file = request.files.get('afiche_evento')
        fondo_file = request.files.get('fondo_evento')

        afiche_path = None
        fondo_path = None

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

        # Insertar nuevo evento en la colección
        collection_eventos.insert_one({
            'nombre': nombre,
            'codigo': codigo,
            'unidad_ejecutora': unidad_ejecutora,
            'tipo': tipo,
            'descripcion': descripcion,
            'fecha_inicio': fecha_inicio,
            'fecha_fin': fecha_fin,
            'afiche': afiche_path if afiche_file else None,
            'afiche_750': resized_afiche_path if afiche_file else None,
            'fondo': fondo_path if fondo_file else None,
            'timestamp': timestamp
        })
        flash("Evento creado con éxito", "success")
        return redirect(url_for('listar_eventos'))  # Redirigir a la lista de eventos

    return render_template('crear_evento.html')


###
### Editar evento
###
@app.route('/editar_evento/<codigo_evento>', methods=['GET', 'POST'])
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
        descripcion = request.form['descripcion']

        fecha_inicio_str = request.form['fecha_inicio']
        fecha_fin_str = request.form['fecha_fin']

        fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%d')
        fecha_fin = datetime.strptime(fecha_fin_str, '%Y-%m-%d')

        timestamp = request.form['timestamp']

        # Carga de archivos (opcional)
        afiche_file = request.files.get('afiche_evento')
        fondo_file = request.files.get('fondo_evento')

        afiche_path = evento.get('afiche')
        fondo_path = evento.get('fondo')
        resized_afiche_path = evento.get('afiche_750')

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

        # Actualizar el evento en la base de datos
        collection_eventos.update_one(
            {"codigo": codigo_evento},
            {"$set": {
                'nombre': nombre,
                'unidad_ejecutora': unidad_ejecutora,
                'tipo': tipo,
                'descripcion': descripcion,
                'fecha_inicio': fecha_inicio,
                'fecha_fin': fecha_fin,
                'afiche': afiche_path,
                'afiche_750': resized_afiche_path,
                'fondo': fondo_path
            }}
        )
        
        flash("Evento actualizado con éxito", "success")
        return redirect(url_for('listar_eventos'))  # Redirigir a la lista de eventos

    return render_template('editar_evento.html', evento=evento)


###
### Validación para eliminar evento
###
@app.route('/eliminar_evento/<codigo_evento>', methods=['POST'])
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
@app.route('/eliminar_participante/<codigo_evento>/<cedula>', methods=['POST'])
def eliminar_participante(codigo_evento, cedula):
    # Eliminar el participante específico por cédula y código de evento
    collection_participantes.delete_one({"cedula": cedula, "codigo_evento": codigo_evento})
    return redirect(url_for('listar_participantes', codigo_evento=codigo_evento))  # Redirigir a la lista de participantes


###
### Página de evento
###
@app.route('/evento/<codigo_evento>', methods=['GET'])
def mostrar_evento(codigo_evento):
    
    evento = collection_eventos.find_one({"codigo": codigo_evento})

    if evento:
        
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
                return render_template('certificado_validado.html', participante=participante, evento=evento)
            else:
                flash("Evento no encontrado. Por favor, verifique el nanoid.", "error")
                return redirect(url_for('validar_certificado'))
        else:
            flash("Certificado no válido. Por favor, verifique el código ingresado.", "error")
            return redirect(url_for('validar_certificado'))

    return render_template('validar.html')


###
### Error 404
###
@app.route('/404')
def page_not_found():
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(debug=True)