from flask import Flask, request, render_template, redirect, url_for, flash
from pymongo import MongoClient
from datetime import datetime, timedelta
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


##
## Conexión a MongoDB
##
client = MongoClient('mongodb://localhost:27017/')
db = client['certi_css']
collection_eventos = db['eventos']
collection_participantes = db['participantes']

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
otp_code = ""
otp_valid_until = datetime.now()

def generate_otp():
    """Genera un código OTP de 4 dígitos (mayúsculas y números)."""
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for _ in range(4))

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
### Formulario de registro de participantes
###
@app.route('/registrar/<codigo_evento>')
def index(codigo_evento):
    # Verificar si el código del evento existe en la base de datos
    evento = collection_eventos.find_one({"codigo": codigo_evento})
    
    if evento is None:
        return redirect(url_for('page_not_found'))  # Redirigir a la página 404 si el código no existe
    
    global otp_code, otp_valid_until
    
    # Generar un nuevo OTP cada minuto
    if datetime.now() >= otp_valid_until:
        otp_code = generate_otp()
        otp_valid_until = datetime.now() + timedelta(minutes=1)

    return render_template('index.html', otp=otp_code, codigo_evento=codigo_evento, nombre_evento=evento['nombre'])


@app.route('/registrar', methods=['POST'])
def registrar():
    global otp_code, otp_valid_until
    
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

    # Validar si el registro se realizó durante la validez del OTP y si coincide con el OTP ingresado
    if datetime.now() <= otp_valid_until and otp_ingresado == otp_code:
        
        # Generar nanoid
        nanoid = generate_nanoid(cedula, codigo_evento)
        
        # Insertar datos en la colección de MongoDB
        collection_participantes.insert_one({
            'nombres': nombres,
            'apellidos': apellidos,
            'cedula': cedula,
            'rol': rol,
            'codigo_evento': codigo_evento,
            'otp': otp_code,
            'nanoid': nanoid,
            'timestamp': timestamp
        })

        # Mensaje de éxito o falla en registro
        flash("Registro completado con éxito", "success")
        return redirect(url_for('index', codigo_evento=codigo_evento))
    else:
        flash("El OTP ha expirado o es incorrecto. Por favor, recargue la página.", "error")
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
### Listado de eventos
###
@app.route('/eventos')
def listar_eventos():
    eventos = collection_eventos.find()  # Recuperar todos los eventos de la base de datos
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
        tipo = request.form['tipo']
        fecha_inicio = request.form['fecha_inicio']
        fecha_fin = request.form['fecha_fin']
        timestamp = request.form['timestamp']

        # Obtener un código único
        codigo = obtener_codigo_unico()  # Esta función genera un código único

        # Insertar nuevo evento en la colección
        collection_eventos.insert_one({
            'nombre': nombre,
            'codigo': codigo,
            'tipo': tipo,
            'fecha_inicio': fecha_inicio,
            'fecha_fin': fecha_fin,
            'timestamp': timestamp
        })
        flash("Evento creado con éxito", "success")
        return redirect(url_for('listar_eventos'))  # Redirigir a la lista de eventos

    return render_template('crear_evento.html')


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
### Error 404
###
@app.route('/404')
def page_not_found():
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(debug=True)