from functools import wraps
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from enum import Enum
from typing import Optional, Set, List, Union

collection_usuarios = None

def init_auth_services(usuarios_collection):
    global collection_usuarios
    collection_usuarios = usuarios_collection


class UserRole(str, Enum):
    COORDINADOR_DEPARTAMENTAL = 'coordinador-departamental'
    COORDINADOR_LOCAL = 'coordinador-local'
    COORDINADOR_REGIONAL = 'coordinador-regional'
    COORDINADOR_NACIONAL = 'coordinador-nacional'
    SUBDIRECTOR_DOCENCIA = 'subdirector-docencia'
    COORDINADOR_ADMINISTRATIVO = 'coordinador-administrativo'
    DENADOI = 'denadoi'
    SIMULACION = 'simulacion'
    ADMINISTRADOR = 'administrador'


ALLOWED_USER_ROLES: Set[str] = {
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
    def __init__(
        self,
        email: str,
        password: str,
        rol: str,
        nombres: str,
        apellidos: str,
        cedula: str,
        foto: Optional[str] = None,
        permisos: Optional[List[str]] = None,
        region: Optional[str] = None
    ):
        self.email = email
        self.password = password
        self.rol = rol
        self.nombres = nombres
        self.apellidos = apellidos
        self.cedula = cedula
        self.foto = foto
        self.permisos = permisos if permisos is not None else []
        self.region = region
        self.id: Optional[str] = None

    @property
    def role(self) -> Optional[UserRole]:
        try:
            return UserRole(self.rol)
        except ValueError:
            return None

    def has_role(self, role: Union[UserRole, str]) -> bool:
        role_str = role.value if isinstance(role, UserRole) else str(role)
        return self.rol == role_str

    def has_any_role(self, roles: List[Union[UserRole, str]]) -> bool:
        return any(self.has_role(r) for r in roles)

    def is_admin(self) -> bool:
        return self.rol == UserRole.ADMINISTRADOR.value

    def has_permission(self, permission: str) -> bool:
        if self.is_admin():
            return True
        return permission in self.permisos

    def has_any_permission(self, *permissions: str) -> bool:
        if self.is_admin():
            return True
        return any(permission in self.permisos for permission in permissions)

    def is_authenticated(self) -> bool:
        return True

    def is_active(self) -> bool:
        return True

    def is_anonymous(self) -> bool:
        return False

    def get_id(self) -> str:
        return str(self.id)


def load_user(user_id: str) -> Optional[User]:
    from bson.objectid import ObjectId
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
            permisos=user_data.get('permisos', []),
            region=user_data.get('region', '')
        )
        user.id = str(user_data['_id'])
        return user
    return None


def roles_required(*roles: Union[UserRole, str]):
    allowed = {r.value if isinstance(r, UserRole) else str(r) for r in roles}

    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(*args, **kwargs):
            from flask_login import current_user
            from flask import abort
            if not current_user.is_authenticated:
                from flask_login import LoginManager
                login_manager = LoginManager()
                return login_manager.unauthorized()
            if current_user.rol not in allowed:
                abort(403)
            return view_func(*args, **kwargs)
        return wrapped_view
    return decorator


def role_required(role: Union[UserRole, str]):
    return roles_required(role)


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    return check_password_hash(stored_hash, password)


def validate_user_credentials(email: str, password: str) -> Optional[dict]:
    from bson.objectid import ObjectId
    user_data = collection_usuarios.find_one({"email": email})
    if not user_data:
        return None
    if not verify_password(user_data['password'], password):
        return None
    return {
        'id': str(user_data['_id']),
        'email': user_data['email'],
        'rol': user_data['rol'],
        'cedula': user_data.get('cedula', ''),
        'nombres': user_data.get('nombres', ''),
        'apellidos': user_data.get('apellidos', '')
    }


def create_user_session(email: str) -> Optional[dict]:
    from bson.objectid import ObjectId
    from datetime import datetime, timedelta
    user_data = collection_usuarios.find_one({"email": email})
    if not user_data:
        return None
    collection_usuarios.update_one(
        {"email": email},
        {"$set": {"failed_attempts": 0, "last_failed_attempt": None, "blocked_until": None}}
    )
    return {
        'id': str(user_data['_id']),
        'email': user_data['email'],
        'rol': user_data['rol']
    }


def record_failed_login_attempt(email: str) -> dict:
    from datetime import datetime, timedelta
    user_data = collection_usuarios.find_one({"email": email})
    if not user_data:
        return {'blocked': False}
    
    failed_attempts = user_data.get('failed_attempts', 0) + 1
    last_failed_attempt = datetime.utcnow()

    if failed_attempts >= 5:
        blocked_until = last_failed_attempt + timedelta(minutes=15)
        collection_usuarios.update_one(
            {"email": email},
            {"$set": {"failed_attempts": failed_attempts, "last_failed_attempt": last_failed_attempt, "blocked_until": blocked_until}}
        )
        return {'blocked': True, 'blocked_until': blocked_until}
    else:
        collection_usuarios.update_one(
            {"email": email},
            {"$set": {"failed_attempts": failed_attempts, "last_failed_attempt": last_failed_attempt}}
        )
        return {'blocked': False, 'failed_attempts': failed_attempts}


def check_user_blocked(email: str) -> tuple:
    from datetime import datetime
    user_data = collection_usuarios.find_one({"email": email})
    if not user_data:
        return False, None
    blocked_until = user_data.get('blocked_until')
    if blocked_until and blocked_until > datetime.utcnow():
        return True, blocked_until
    return False, None


def check_user_active(email: str) -> bool:
    user_data = collection_usuarios.find_one({"email": email})
    if not user_data:
        return False
    return user_data.get('activo', False)


import secrets
from datetime import datetime, timedelta

collection_tokens = None

def init_token_services(tokens_collection):
    global collection_tokens
    collection_tokens = tokens_collection


def generate_token(cedula: str) -> str:
    token = secrets.token_urlsafe(32)
    expiry = datetime.now() + timedelta(hours=2)
    collection_tokens.update_one(
        {'cedula': cedula},
        {'$set': {'token': token, 'expiry': expiry}},
        upsert=True
    )
    return token


def verify_token(cedula: str, token: str) -> bool:
    token_data = collection_tokens.find_one({'cedula': cedula})
    if not token_data:
        return False
    if datetime.now() > token_data['expiry']:
        collection_tokens.delete_one({'cedula': cedula})
        return False
    return token_data['token'] == token


def lms_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask_login import current_user
        from flask import abort
        if not current_user.is_authenticated:
            abort(401)
        if current_user.rol == 'administrador':
            return f(*args, **kwargs)
        if current_user.rol == 'denadoi':
            return f(*args, **kwargs)
        permisos_usuario = getattr(current_user, 'permisos', [])
        if 'lms_admin' in permisos_usuario or 'lms_edit' in permisos_usuario:
            return f(*args, **kwargs)
        abort(403)
    return decorated_function


def lms_edit_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask_login import current_user
        from flask import abort
        if not current_user.is_authenticated:
            abort(401)
        if current_user.rol in ['administrador', 'denadoi']:
            return f(*args, **kwargs)
        permisos_usuario = getattr(current_user, 'permisos', [])
        if 'lms_admin' in permisos_usuario:
            return f(*args, **kwargs)
        if 'lms_edit' in permisos_usuario:
            codigo_qbank = kwargs.get('codigo_qbank')
            if codigo_qbank:
                from app import collection_qbanks
                qbank = collection_qbanks.find_one({"codigo": codigo_qbank})
                if qbank and qbank.get('autor') == current_user.id:
                    return f(*args, **kwargs)
                else:
                    abort(403)
            else:
                return f(*args, **kwargs)
        abort(403)
    return decorated_function


def permission_required(*permisos):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask_login import current_user
            from flask import abort
            if not current_user.is_authenticated:
                abort(401)
            if current_user.rol == 'administrador':
                return f(*args, **kwargs)
            permisos_usuario = getattr(current_user, 'permisos', [])
            if not permisos_usuario:
                from app import collection_usuarios
                from bson.objectid import ObjectId
                user_data = collection_usuarios.find_one({"_id": ObjectId(current_user.id)})
                permisos_usuario = user_data.get('permisos', []) if user_data else []
                current_user.permisos = permisos_usuario
            if any(permiso in permisos_usuario for permiso in permisos):
                return f(*args, **kwargs)
            abort(403)
        return decorated_function
    return decorator


def token_required(f):
    @wraps(f)
    def decorated_function(codigo_evento, *args, **kwargs):
        from flask_login import current_user
        from flask import request, abort
        if (current_user.is_authenticated 
            and current_user.rol == 'administrador' 
            and request.path.startswith('/plataforma')):
            return f(codigo_evento, *args, **kwargs)
        token = request.args.get('token')
        cedula = request.args.get('cedula')
        if not cedula or not token or not verify_token(cedula, token):
            abort(401)
        return f(codigo_evento, *args, **kwargs)
    return decorated_function
