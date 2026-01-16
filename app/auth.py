from functools import wraps
import secrets
from flask_login import current_user
from flask import request, Blueprint, abort
from datetime import datetime, timedelta
from app import db, collection_tokens


auth_bp = Blueprint('auth', __name__)


###
### Decorador de permisos LMS
###
def lms_required(f):
    """
    Decorador que verifica si el usuario tiene permisos completos en el LMS.
    Tienen acceso:
    - Administradores
    - Rol 'denadoi'
    - Usuarios con permiso 'lms_admin'
    - Usuarios con permiso 'lms_edit' (acceso limitado)
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        
        # Administradores siempre tienen acceso
        if current_user.rol == 'administrador':
            return f(*args, **kwargs)
        
        # Rol denadoi tiene acceso
        if current_user.rol == 'denadoi':
            return f(*args, **kwargs)
        
        # Verificar si tiene el permiso lms_admin o lms_edit
        permisos_usuario = getattr(current_user, 'permisos', [])
        if 'lms_admin' in permisos_usuario or 'lms_edit' in permisos_usuario:
            return f(*args, **kwargs)
        
        # Si no cumple ninguna condición, denegar acceso
        abort(403)
    
    return decorated_function


###
### Decorador de permisos LMS Edit (acceso limitado)
###
def lms_edit_required(f):
    """
    Decorador que verifica si el usuario tiene permisos de edición limitados en el LMS.
    Tienen acceso:
    - Administradores (acceso completo)
    - Rol 'denadoi' (acceso completo)
    - Usuarios con permiso 'lms_admin' (acceso completo)
    - Usuarios con permiso 'lms_edit' (acceso limitado a sus propios QBanks)
    
    Para rutas de QBanks, verifica que el usuario sea el autor del QBank.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        
        # Administradores y denadoi siempre tienen acceso completo
        if current_user.rol in ['administrador', 'denadoi']:
            return f(*args, **kwargs)
        
        # Verificar permisos
        permisos_usuario = getattr(current_user, 'permisos', [])
        
        # lms_admin tiene acceso completo
        if 'lms_admin' in permisos_usuario:
            return f(*args, **kwargs)
        
        # lms_edit tiene acceso limitado
        if 'lms_edit' in permisos_usuario:
            # Si la ruta incluye codigo_qbank, verificar que sea el autor
            codigo_qbank = kwargs.get('codigo_qbank')
            if codigo_qbank:
                from app import collection_qbanks
                qbank = collection_qbanks.find_one({"codigo": codigo_qbank})
                if qbank and qbank.get('autor') == current_user.id:
                    return f(*args, **kwargs)
                else:
                    abort(403)  # No es el autor del QBank
            else:
                # Para rutas sin codigo_qbank (como crear nuevo), permitir acceso
                return f(*args, **kwargs)
        
        # Si no cumple ninguna condición, denegar acceso
        abort(403)
    
    return decorated_function


###
### Decorador de permisos
###
def permission_required(*permisos):
    """
    Decorador que verifica si el usuario tiene al menos uno de los permisos especificados.
    Los administradores siempre tienen acceso.
    
    Uso:
        @permission_required('lms_admin', 'lms_view')
        def mi_ruta():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            
            # Los administradores siempre tienen acceso
            if current_user.rol == 'administrador':
                return f(*args, **kwargs)
            
            # Verificar si el usuario tiene alguno de los permisos requeridos
            permisos_usuario = getattr(current_user, 'permisos', [])
            if not permisos_usuario:
                # Si el usuario no tiene el atributo permisos, cargar desde la base de datos
                from app import collection_usuarios
                from bson import ObjectId
                user_data = collection_usuarios.find_one({"_id": ObjectId(current_user.id)})
                permisos_usuario = user_data.get('permisos', []) if user_data else []
                current_user.permisos = permisos_usuario
            
            # Verificar si tiene al menos uno de los permisos requeridos
            if any(permiso in permisos_usuario for permiso in permisos):
                return f(*args, **kwargs)
            
            # Si no tiene permisos, denegar acceso
            abort(403)
        
        return decorated_function
    return decorator


###
### Tokens EVA
###
def generate_token(cedula):
    """Genera un token único para una cédula"""
    token = secrets.token_urlsafe(32)
    expiry = datetime.now() + timedelta(hours=2)
    
    # Almacenar token en MongoDB
    collection_tokens.update_one(
        {'cedula': cedula},
        {'$set': {'token': token, 'expiry': expiry}},
        upsert=True
    )
    
    return token

def verify_token(cedula, token):
    """Verifica si el token es válido para la cédula dada"""
    token_data = collection_tokens.find_one({'cedula': cedula})
    
    if not token_data:
        return False
    
    # Verificar expiración
    if datetime.now() > token_data['expiry']:
        collection_tokens.delete_one({'cedula': cedula})
        return False
    
    return token_data['token'] == token

def token_required(f):
    @wraps(f)
    def decorated_function(codigo_evento, *args, **kwargs):

        # Bypass admins
        if (current_user.is_authenticated 
            and current_user.rol == 'administrador' 
            and request.path.startswith('/plataforma')):
            return f(codigo_evento, *args, **kwargs)

        # Verificación por token
        token = request.args.get('token')
        cedula = request.args.get('cedula')
        
        if not cedula or not token or not verify_token(cedula, token):
            abort(401)
        
        return f(codigo_evento, *args, **kwargs)
    return decorated_function
