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
    if collection_failed_attempts is not None:
        collection_failed_attempts.delete_one({"unknown_email": email})
    return {
        'id': str(user_data['_id']),
        'email': user_data['email'],
        'rol': user_data['rol']
    }


def record_failed_login_attempt(email: str) -> dict:
    from datetime import datetime, timedelta
    from flask import current_app

    max_attempts = current_app.config.get('MAX_LOGIN_ATTEMPTS', 5)
    lockout_minutes = current_app.config.get('ACCOUNT_LOCKOUT_MINUTES', 15)
    now = datetime.utcnow()

    user_data = collection_usuarios.find_one({"email": email})
    if user_data:
        failed_attempts = user_data.get('failed_attempts', 0) + 1
        if failed_attempts >= max_attempts:
            blocked_until = now + timedelta(minutes=lockout_minutes)
            collection_usuarios.update_one(
                {"email": email},
                {"$set": {"failed_attempts": failed_attempts, "last_failed_attempt": now, "blocked_until": blocked_until}}
            )
            return {'blocked': True, 'blocked_until': blocked_until}
        else:
            collection_usuarios.update_one(
                {"email": email},
                {"$set": {"failed_attempts": failed_attempts, "last_failed_attempt": now}}
            )
            return {'blocked': False, 'failed_attempts': failed_attempts}

    if collection_failed_attempts is None:
        return {'blocked': False}

    record = collection_failed_attempts.find_one({"unknown_email": email})
    if record:
        failed_attempts = record['attempts'] + 1
        if failed_attempts >= max_attempts:
            blocked_until = now + timedelta(minutes=lockout_minutes)
            collection_failed_attempts.update_one(
                {"unknown_email": email},
                {"$set": {"attempts": failed_attempts, "last_attempt": now, "blocked_until": blocked_until}}
            )
            return {'blocked': True, 'blocked_until': blocked_until}
        else:
            collection_failed_attempts.update_one(
                {"unknown_email": email},
                {"$set": {"attempts": failed_attempts, "last_attempt": now}}
            )
            return {'blocked': False, 'failed_attempts': failed_attempts}
    else:
        collection_failed_attempts.insert_one({
            "unknown_email": email,
            "attempts": 1,
            "last_attempt": now,
            "blocked_until": None
        })
        return {'blocked': False, 'failed_attempts': 1}


def check_user_blocked(email: str) -> tuple:
    from datetime import datetime
    user_data = collection_usuarios.find_one({"email": email})
    if user_data:
        blocked_until = user_data.get('blocked_until')
        if blocked_until and blocked_until > datetime.utcnow():
            return True, blocked_until
        if blocked_until and blocked_until <= datetime.utcnow():
            collection_usuarios.update_one(
                {"email": email},
                {"$set": {"failed_attempts": 0, "blocked_until": None}}
            )
        return False, None

    if collection_failed_attempts is not None:
        record = collection_failed_attempts.find_one({"unknown_email": email})
        if record:
            blocked_until = record.get('blocked_until')
            if blocked_until and blocked_until > datetime.utcnow():
                return True, blocked_until
            if blocked_until and blocked_until <= datetime.utcnow():
                collection_failed_attempts.delete_one({"unknown_email": email})
    return False, None


def check_user_active(email: str) -> bool:
    user_data = collection_usuarios.find_one({"email": email})
    if not user_data:
        return False
    return user_data.get('activo', False)


def record_failed_ip_attempt(ip_address: str) -> dict:
    from datetime import datetime, timedelta
    from flask import current_app
    if collection_failed_attempts is None:
        return {'blocked': False}
    now = datetime.utcnow()
    max_attempts = current_app.config.get('MAX_IP_ATTEMPTS', 20)
    lockout_minutes = current_app.config.get('IP_LOCKOUT_MINUTES', 30)
    record = collection_failed_attempts.find_one({"ip": ip_address})
    if record:
        attempts = record['attempts'] + 1
        if attempts >= max_attempts:
            blocked_until = now + timedelta(minutes=lockout_minutes)
            collection_failed_attempts.update_one(
                {"ip": ip_address},
                {"$set": {"attempts": attempts, "last_attempt": now, "blocked_until": blocked_until}}
            )
            return {'blocked': True, 'blocked_until': blocked_until}
        else:
            collection_failed_attempts.update_one(
                {"ip": ip_address},
                {"$set": {"attempts": attempts, "last_attempt": now}}
            )
            return {'blocked': False, 'attempts': attempts}
    else:
        collection_failed_attempts.insert_one({
            "ip": ip_address,
            "attempts": 1,
            "last_attempt": now,
            "blocked_until": None
        })
        return {'blocked': False, 'attempts': 1}


def check_ip_blocked(ip_address: str) -> tuple:
    from datetime import datetime
    if collection_failed_attempts is None:
        return False, None
    record = collection_failed_attempts.find_one({"ip": ip_address})
    if not record:
        return False, None
    blocked_until = record.get('blocked_until')
    if blocked_until and blocked_until > datetime.utcnow():
        return True, blocked_until
    if blocked_until and blocked_until <= datetime.utcnow():
        collection_failed_attempts.delete_one({"ip": ip_address})
    return False, None


def generate_csrf_token() -> str:
    import secrets
    from flask import session
    token = secrets.token_hex(32)
    session['csrf_token'] = token
    return token


def validate_csrf_token(token: str) -> bool:
    from flask import session
    stored = session.pop('csrf_token', None)
    if not stored or not token:
        return False
    return stored == token


import secrets
from datetime import datetime, timedelta

collection_tokens = None

def init_token_services(tokens_collection):
    global collection_tokens
    collection_tokens = tokens_collection


collection_failed_attempts = None

def init_rate_limit_services(failed_attempts_collection):
    global collection_failed_attempts
    collection_failed_attempts = failed_attempts_collection


def get_client_ip() -> str:
    from flask import request
    if request.headers.get('X-Forwarded-For'):
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr or 'unknown'


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
