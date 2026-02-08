###
###
###  Este archivo contiene funciones relacionadas con la administración de usuarios
###  de CertiCSS y con el inicio y cierres de sesión.
###
###
from flask import Blueprint, request, render_template, redirect, url_for, flash, session, abort
from flask_login import LoginManager, login_user, UserMixin, logout_user, current_user, login_required
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from PIL import Image
from functools import wraps
import os

# Crear el blueprint
usuarios_bp = Blueprint('usuarios', __name__)

# Importar las colecciones de MongoDB desde el módulo principal
# Estas se configurarán cuando se registre el blueprint
collection_usuarios = None
collection_participantes = None
app_config = None
log_event = None

def init_usuarios_module(usuarios_collection, participantes_collection, config, log_function):
    """Inicializar el módulo con las dependencias necesarias"""
    global collection_usuarios, collection_participantes, app_config, log_event
    collection_usuarios = usuarios_collection
    collection_participantes = participantes_collection
    app_config = config
    log_event = log_function

# Enum de roles de usuario (copiado desde app.py)
from enum import Enum

class UserRole(str, Enum):
    COORDINADOR_DEPARTAMENTAL = 'coordinador-departamental'
    COORDINADOR_LOCAL = 'coordinador-local'
    COORDINADOR_REGIONAL = 'coordinador-regional'
    COORDINADOR_NACIONAL = 'coordinador-nacional'
    SUBDIRECTOR_DOCENCIA = 'subdirector-docencia'
    COORDINADOR_ADMINISTRATIVO = 'coordinador-administrativo'
    DENADOI = 'denadoi'
    SIMULACION = 'simulacion'
    ADMINISTRADOR = 'administrador'  # Reservado, no se crea desde el formulario

ALLOWED_USER_ROLES = {
    UserRole.COORDINADOR_DEPARTAMENTAL.value,
    UserRole.COORDINADOR_LOCAL.value,
    UserRole.COORDINADOR_REGIONAL.value,
    UserRole.COORDINADOR_NACIONAL.value,
    UserRole.SUBDIRECTOR_DOCENCIA.value,
    UserRole.COORDINADOR_ADMINISTRATIVO.value,
    UserRole.DENADOI.value,
    UserRole.SIMULACION.value,
}

class User(UserMixin):
    def __init__(self, email, password, rol, nombres, apellidos, cedula, foto=None, permisos=None):
        self.email = email
        self.password = password
        self.rol = rol
        self.nombres = nombres
        self.apellidos = apellidos
        self.cedula = cedula
        self.foto = foto
        self.permisos = permisos if permisos is not None else []
        self.id = None

    @property
    def role(self):
        try:
            return UserRole(self.rol)
        except ValueError:
            return None

    def has_role(self, role):
        role_str = role.value if isinstance(role, UserRole) else str(role)
        return self.rol == role_str

    def has_any_role(self, roles):
        return any(self.has_role(r) for r in roles)

    def is_admin(self):
        return self.rol == UserRole.ADMINISTRADOR.value
    
    def has_permission(self, permission):
        """Verifica si el usuario tiene un permiso específico"""
        if self.is_admin():
            return True
        return permission in self.permisos
    
    def has_any_permission(self, *permissions):
        """Verifica si el usuario tiene al menos uno de los permisos especificados"""
        if self.is_admin():
            return True
        return any(permission in self.permisos for permission in permissions)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

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
            foto=user_data.get('foto'),
            permisos=user_data.get('permisos', [])
        )
        user.id = str(user_data['_id'])
        return user
    return None

def roles_required(*roles):
    allowed = {r.value if isinstance(r, UserRole) else str(r) for r in roles}
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(*args, **kwargs):
            if not current_user.is_authenticated:
                from flask_login import LoginManager
                login_manager = LoginManager()
                return login_manager.unauthorized()
            if current_user.rol not in allowed:
                abort(403)
            return view_func(*args, **kwargs)
        return wrapped_view
    return decorator

def role_required(role):
    return roles_required(role)

def allowed_file(filename):
    """Función auxiliar para validar archivos permitidos"""
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

###
### Página de registro
###
@usuarios_bp.route('/tablero/usuarios/registrar', methods=['GET', 'POST'])
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

        # Validar rol permitido
        if rol not in ALLOWED_USER_ROLES and rol != UserRole.ADMINISTRADOR.value:
            flash('Rol inválido.', 'error')
            return redirect(url_for('usuarios.registro'))

        # Verificar si el usuario ya existe
        if collection_usuarios.find_one({"email": email}):
            flash('El usuario ya existe.')
            return redirect(url_for('usuarios.registro'))

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
            'permisos': [],  # Inicializar sin permisos adicionales
            'timestamp': timestamp
        })
        log_event(f"Usuario [{current_user.email}] registró un nuevo usuario: {email}.")
        return redirect(url_for('usuarios.listar_usuarios'))

    return render_template('registrar_usuario.html')

###
### Login
###
@usuarios_bp.route('/iniciar_sesion', methods=['GET', 'POST'])
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
@usuarios_bp.route('/tablero/usuarios')
@usuarios_bp.route('/tablero/usuarios/page/<int:page>')
@login_required
def listar_usuarios(page=1):
    # Obtener todos los usuarios (sin paginación para poder ordenar correctamente)
    usuarios_cursor = collection_usuarios.find({"rol": {"$ne": "administrador"}})
    usuarios = list(usuarios_cursor)

    # Agregar foto_url a cada usuario
    for usuario in usuarios:
        usuario['foto_url'] = f"/static/usuarios/{usuario['foto']}" if usuario.get('foto') else "/static/assets/user-avatar.png"

    # Función para ordenar usuarios según los criterios especificados
    def ordenar_usuarios(usuarios):
        usuarios_ordenados = []
        
        # 1. Primero usuarios DENADOI (jefe, subjefe, luego otros)
        denadoi_jefe = [u for u in usuarios if u.get('rol') == 'denadoi' and u.get('jefe', False)]
        denadoi_subjefe = [u for u in usuarios if u.get('rol') == 'denadoi' and u.get('subjefe', False)]
        denadoi_otros = [u for u in usuarios if u.get('rol') == 'denadoi' and not u.get('jefe', False) and not u.get('subjefe', False)]
        
        # Ordenar cada grupo por apellidos y nombres
        for grupo in [denadoi_jefe, denadoi_subjefe, denadoi_otros]:
            grupo.sort(key=lambda x: (x.get('apellidos', ''), x.get('nombres', '')))
        
        usuarios_ordenados.extend(denadoi_jefe)
        usuarios_ordenados.extend(denadoi_subjefe)
        usuarios_ordenados.extend(denadoi_otros)
        
        # 2. Luego usuarios por provincia/región (excluyendo DENADOI, coordinador-administrativo y simulacion)
        regiones_orden = ['css01', 'css02', 'css03', 'css04', 'css06', 'css07', 'css09', 'css13', 'css082', 'css081', 'css088']
        roles_orden = ['coordinador-regional', 'subdirector-docencia', 'coordinador-local', 'coordinador-departamental']
        
        for region in regiones_orden:
            usuarios_region = [u for u in usuarios if u.get('region') == region and u.get('rol') not in ['denadoi', 'coordinador-administrativo', 'simulacion']]
            if usuarios_region:
                # Ordenar por rol según el orden especificado, luego por apellidos y nombres
                usuarios_region.sort(key=lambda x: (
                    roles_orden.index(x.get('rol')) if x.get('rol') in roles_orden else 999,
                    x.get('apellidos', ''),
                    x.get('nombres', '')
                ))
                usuarios_ordenados.extend(usuarios_region)
        
        # 3. Finalmente usuarios administrativos (coordinador-administrativo y simulacion)
        usuarios_admin = [u for u in usuarios if u.get('rol') in ['coordinador-administrativo', 'simulacion']]
        usuarios_admin.sort(key=lambda x: (x.get('apellidos', ''), x.get('nombres', '')))
        usuarios_ordenados.extend(usuarios_admin)
        
        return usuarios_ordenados

    # Aplicar el ordenamiento
    usuarios_ordenados = ordenar_usuarios(usuarios)
    
    # Aplicar paginación después del ordenamiento
    usuarios_por_pagina = 20
    total_usuarios = len(usuarios_ordenados)
    total_paginas = (total_usuarios + usuarios_por_pagina - 1) // usuarios_por_pagina
    
    inicio = (page - 1) * usuarios_por_pagina
    fin = inicio + usuarios_por_pagina
    usuarios_pagina = usuarios_ordenados[inicio:fin]

    # Determinar qué separadores mostrar en esta página
    separadores_mostrar = {
        'denadoi': False,
        'regiones': [],
        'administrativos': False
    }
    
    # Verificar si es la primera aparición de cada grupo en esta página
    if usuarios_pagina:
        # Verificar usuarios anteriores a esta página para saber qué separadores ya se mostraron
        usuarios_anteriores = usuarios_ordenados[:inicio] if inicio > 0 else []
        
        # Verificar qué grupos ya aparecieron antes de esta página
        grupos_anteriores = {
            'denadoi': any(u.get('rol') == 'denadoi' for u in usuarios_anteriores),
            'regiones': set(u.get('region') for u in usuarios_anteriores if u.get('rol') not in ['denadoi', 'coordinador-administrativo', 'simulacion']),
            'administrativos': any(u.get('rol') in ['coordinador-administrativo', 'simulacion'] for u in usuarios_anteriores)
        }
        
        # Determinar qué separadores mostrar en esta página
        for usuario in usuarios_pagina:
            if usuario.get('rol') == 'denadoi' and not grupos_anteriores['denadoi']:
                separadores_mostrar['denadoi'] = True
                grupos_anteriores['denadoi'] = True
            
            if (usuario.get('rol') not in ['denadoi', 'coordinador-administrativo', 'simulacion'] and 
                usuario.get('region') not in grupos_anteriores['regiones']):
                if usuario.get('region') not in separadores_mostrar['regiones']:
                    separadores_mostrar['regiones'].append(usuario.get('region'))
                grupos_anteriores['regiones'].add(usuario.get('region'))
            
            if (usuario.get('rol') in ['coordinador-administrativo', 'simulacion'] and 
                not grupos_anteriores['administrativos']):
                separadores_mostrar['administrativos'] = True
                grupos_anteriores['administrativos'] = True

    return render_template('usuarios.html',
        usuarios=usuarios_pagina,
        usuarios_todos=usuarios_ordenados,  # Para el template
        separadores_mostrar=separadores_mostrar,
        page=page,
        total_paginas=total_paginas,
        total_usuarios=total_usuarios
    )

###
### Edición de perfil de usuario
###
@usuarios_bp.route('/tablero/usuarios/<user_id>/editar', methods=['GET', 'POST'])
@login_required
def editar_usuario(user_id):
    if request.method == 'POST':
        usuario = collection_usuarios.find_one({"_id": ObjectId(user_id)})
        if not usuario:
            return redirect(url_for('usuarios.listar_usuarios'))

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

        # Validar rol permitido
        if rol not in ALLOWED_USER_ROLES and rol != UserRole.ADMINISTRADOR.value:
            flash('Rol inválido.', 'error')
            return redirect(url_for('usuarios.editar_usuario', user_id=user_id))

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
            foto_path = os.path.join(app_config['USERS_FOLDER'], foto_filename)

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
        return redirect(url_for('usuarios.listar_usuarios'))  # Redirigir a la lista de usuarios

    # Obtener los datos del usuario
    usuario = collection_usuarios.find_one({"_id": ObjectId(user_id)})

    if usuario.get('foto'):
        foto_url = f"/static/usuarios/{usuario['foto']}"
    else:
        foto_url = None

    return render_template('editar_usuario.html', usuario=usuario, foto_url=foto_url)


###
### Eliminar foto de perfil
###
@usuarios_bp.route('/tablero/usuarios/<user_id>/eliminar_foto', methods=['POST'])
@login_required
def eliminar_foto(user_id):
    print(f"Intentando eliminar la foto del usuario: {user_id}")  # Debug

    usuario = collection_usuarios.find_one({"_id": ObjectId(user_id)})

    if not usuario or not usuario.get("foto"):
        print("No se encontró una foto asociada en la base de datos.")  # Debug
        return redirect(url_for('usuarios.editar_usuario', user_id=user_id))

    # Ruta de la foto en el servidor
    foto_path = os.path.join(app_config['USERS_FOLDER'], f"{user_id}-foto.jpg")
    print(f"Ruta de la foto: {foto_path}")  # Debug
    print(f"Existe en el servidor: {os.path.exists(foto_path)}")  # Debug

    # Eliminar la foto
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

    return redirect(url_for('usuarios.editar_usuario', user_id=user_id))


###
### Perfil de usuario
###
@usuarios_bp.route('/tablero/usuarios/<user_id>')
@login_required
def mostrar_usuario(user_id):
    # Obtener los datos del usuario desde la base de datos usando el user_id
    usuario = collection_usuarios.find_one({"_id": ObjectId(user_id)})

    foto_url = f"/static/usuarios/{usuario['foto']}" if usuario.get('foto') else None

    if not usuario:
        flash("Usuario no encontrado", "danger")
        return redirect(url_for('usuarios.listar_usuarios'))  # Redirigir a la lista de usuarios si no se encuentra

    return render_template('perfil_usuario.html', usuario=usuario, foto_url=foto_url)


###
### Acciones de usuario
###
@usuarios_bp.route('/tablero/usuarios/<user_id>/eliminar', methods=['POST'])
@login_required
def eliminar_usuario(user_id):
    if current_user.rol != 'administrador':
        flash('No tienes permisos para realizar esta acción.', 'error')
        return redirect(url_for('usuarios.listar_usuarios'))

    # Obtener el usuario que se va a eliminar
    usuario = collection_usuarios.find_one({"_id": ObjectId(user_id)})

    if not usuario:
        flash('Usuario no encontrado.', 'error')
        return redirect(url_for('usuarios.listar_usuarios'))

    # Obtener el email del usuario que se va a eliminar
    email = usuario.get('email')

    # Eliminar el usuario de la base de datos
    collection_usuarios.delete_one({"_id": ObjectId(user_id)})

    log_event(f"Usuario [{current_user.email}] eliminó el usuario {email}.")
    flash('Usuario eliminado con éxito.')
    return redirect(url_for('usuarios.listar_usuarios'))


###
### Activar/desactivar usuario
###
@usuarios_bp.route('/tablero/usuarios/<user_id>/toggle_activo', methods=['POST'])
@login_required
def toggle_activo(user_id):
    # Get target user
    usuario = collection_usuarios.find_one({"_id": ObjectId(user_id)})
    if not usuario:
        flash('Usuario no encontrado.', 'error')
        return redirect(url_for('usuarios.listar_usuarios'))

    # Permission checks
    puede_modificar = False
    
    # 1. Administrators can modify anyone
    if current_user.rol == 'administrador':
        puede_modificar = True
    
    # 2. DENADOI users can modify anyone except jefe and subjefe DENADOI
    elif current_user.rol == 'denadoi':
        es_jefe_denadoi = usuario.get('rol') == 'denadoi' and usuario.get('jefe', False)
        es_subjefe_denadoi = usuario.get('rol') == 'denadoi' and usuario.get('subjefe', False)
        
        if es_jefe_denadoi or es_subjefe_denadoi:
            flash('No puedes modificar el estado del jefe o subjefe de DENADOI.', 'error')
            return redirect(url_for('usuarios.listar_usuarios'))
        
        puede_modificar = True
    
    # 3. Regional coordinators can modify users in their region (except themselves)
    elif current_user.rol == 'coordinador-regional':
        # Cannot modify themselves
        if str(current_user.id) == str(usuario.get('_id')):
            flash('No puedes modificar tu propio estado.', 'error')
            return redirect(url_for('usuarios.listar_usuarios'))
        
        # Can only modify users in the same region
        if current_user.region == usuario.get('region'):
            puede_modificar = True
        else:
            flash('Solo puedes modificar usuarios de tu región.', 'error')
            return redirect(url_for('usuarios.listar_usuarios'))
    
    if not puede_modificar:
        flash('No tienes permisos para realizar esta acción.', 'error')
        return redirect(url_for('usuarios.listar_usuarios'))

    email = usuario.get('email')

    # Cambiar el estado de "activo"
    nuevo_estado = not usuario.get('activo', False)
    collection_usuarios.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"activo": nuevo_estado}}
    )

    log_event(f"Usuario [{current_user.email}] cambió el estado de {email} a {'activo' if nuevo_estado else 'inactivo'}.")
    return redirect(url_for('usuarios.listar_usuarios'))


###
### Cerrar sesión
###
@usuarios_bp.route('/salir', methods=['POST'])
def salir():
    logout_user()
    return redirect(url_for('home'))