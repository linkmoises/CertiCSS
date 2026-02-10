"""
Módulo de Verificación de Encuestas Completadas

Este módulo proporciona funciones para verificar y registrar el estado de completitud
de encuestas para el sistema de gestión de certificados CertiCSS. Hace cumplir los
requisitos de completitud de encuestas para eventos Survey_V2 antes de permitir
la descarga de certificados.

Funciones:
    - has_completed_survey_v2: Verificar si un participante completó Survey_V2
    - record_survey_completion: Registrar la completitud de una encuesta
    - is_participant_registered: Verificar el registro de un participante
    - requires_survey_completion: Verificar si un evento requiere completar la encuesta
"""

from pymongo import MongoClient, errors
from datetime import datetime
from config import config
import logging

# Configurar logger
logger = logging.getLogger('certicss_logger')

# Conexión a MongoDB
client = MongoClient(config.MONGO_URI)
db = client['certi_css']
collection_encuestas_v2 = db['encuestas_v2']
collection_participantes = db['participantes']
collection_eventos = db['eventos']


def has_completed_survey_v2(cedula: str, codigo_evento: str) -> bool:
    """
    Verificar si un participante ha completado Survey_V2 para un evento.
    
    Args:
        cedula: Cédula del participante
        codigo_evento: Código del evento
        
    Returns:
        True si la encuesta fue completada, False en caso contrario
    """
    try:
        # Consultar registro de completitud de encuesta
        record = collection_encuestas_v2.find_one({
            'cedula': cedula,
            'codigo_evento': codigo_evento
        })
        
        return record is not None
        
    except Exception as e:
        logger.error(f"Error checking survey completion for cedula {cedula}, event {codigo_evento}: {e}")
        return False


def record_survey_completion(cedula: str, codigo_evento: str, respuestas: dict) -> bool:
    """
    Registrar que un participante completó Survey_V2.
    
    Args:
        cedula: Cédula del participante
        codigo_evento: Código del evento
        respuestas: Datos de respuestas de la encuesta
        
    Returns:
        True si se registró exitosamente, False si es duplicado o hay error
    """
    try:
        # Preparar registro de completitud de encuesta
        survey_record = {
            'cedula': cedula,
            'codigo_evento': codigo_evento,
            'respuestas': respuestas,
            'fecha': datetime.now()
        }
        
        # Insertar el registro
        collection_encuestas_v2.insert_one(survey_record)
        logger.info(f"Survey completion recorded for cedula {cedula}, event {codigo_evento}")
        return True
        
    except errors.DuplicateKeyError:
        # Intento de envío duplicado de encuesta
        logger.warning(f"Duplicate survey submission attempt for cedula {cedula}, event {codigo_evento}")
        return False
        
    except Exception as e:
        logger.error(f"Error recording survey completion for cedula {cedula}, event {codigo_evento}: {e}")
        return False


def is_participant_registered(cedula: str, codigo_evento: str) -> bool:
    """
    Verificar si una cédula está registrada para un evento.
    
    Args:
        cedula: Cédula del participante
        codigo_evento: Código del evento
        
    Returns:
        True si está registrado, False en caso contrario
    """
    try:
        # Consultar registro de participante
        participant = collection_participantes.find_one({
            'cedula': cedula,
            'codigo_evento': codigo_evento
        })
        
        return participant is not None
        
    except Exception as e:
        logger.error(f"Error checking participant registration for cedula {cedula}, event {codigo_evento}: {e}")
        return False


def requires_survey_completion(evento: dict) -> bool:
    """
    Determinar si un evento requiere completar la encuesta para descargar el certificado.
    
    Args:
        evento: Documento del evento desde MongoDB
        
    Returns:
        True si el evento usa Survey_V2, False en caso contrario
    """
    if not evento:
        return False
    
    # Verificar si el evento tiene el campo instrumento configurado como 'encuesta_v2'
    instrumento = evento.get('instrumento')
    
    # También verificar nombre de campo alternativo para compatibilidad hacia atrás
    if not instrumento:
        instrumento = evento.get('instrumento_encuesta')
    
    return instrumento == 'encuesta_v2'
