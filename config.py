import os
import random
from datetime import timedelta
import locale

###
### Este es el archivo de configuración de CertiCSS, permite trabajar con mínimos cambios
### en un versión en desarrollo y luego en producción al empaquetarla en un contenedor.
###
class Config:
    # Configuraciones comunes
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(24))            # Clave secreta aleatoria por defecto
    UPLOAD_FOLDER = 'static/uploads'                                # Carpeta para subir archivos
    USERS_FOLDER = 'static/usuarios'                                # Carpeta para fotos de perfil de usuarios
    BASE_URL = os.getenv('BASE_URL', 'http://localhost:5000/')      # URL base por defecto
    HOST = os.getenv('FLASK_HOST', '0.0.0.0')                       # Host por defecto
    PORT = int(os.getenv('FLASK_PORT', 5000))                       # Puerto por defecto
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)              # duración de sesión a 30 minutos
    ALLOWED_EXTENSIONS = ('png', 'jpg', 'jpeg', 'gif')


class DevelopmentConfig(Config):
    # Configuraciones para desarrollo local
    DEBUG = True
    MONGO_URI = 'mongodb://localhost:27017/'                        # MongoDB local

class ProductionConfig(Config):
    # Configuraciones para producción (Docker)
    DEBUG = False
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb://db:27017/')       # MongoDB en Docker

# Seleccionar la configuración según el entorno
env = os.getenv('FLASK_ENV', 'development')                         # Por defecto, usar desarrollo
if env == 'production':
    config = ProductionConfig()
else:
    config = DevelopmentConfig()

# Locale de Panamá para mostrar fechas en español
locale.setlocale(locale.LC_TIME, "es_PA.UTF-8")