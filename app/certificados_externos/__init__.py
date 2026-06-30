from flask import Blueprint
from app import db

certificados_externos_bp = Blueprint('certificados_externos', __name__)

collection_certificados_externos = db['certificados_externos']

from app.certificados_externos import routes
