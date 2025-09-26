from functools import wraps
import secrets
from flask_login import current_user
from flask import request, Blueprint, abort
from datetime import datetime, timedelta
from app import db, collection_tokens


auth_bp = Blueprint('auth', __name__)


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
