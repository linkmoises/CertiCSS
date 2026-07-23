"""
Backfill: Agrega el campo lms_activo a eventos existentes.
- Eventos no-presenciales -> lms_activo = True
- Eventos presenciales -> lms_activo = False
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import collection_eventos

no_presencial = collection_eventos.update_many(
    {"lms_activo": {"$exists": False}, "modalidad": {"$ne": "Presencial"}},
    {"$set": {"lms_activo": True}}
)
print(f"Eventos no-presenciales actualizados: {no_presencial.modified_count}")

presencial = collection_eventos.update_many(
    {"lms_activo": {"$exists": False}, "modalidad": "Presencial"},
    {"$set": {"lms_activo": False}}
)
print(f"Eventos presenciales actualizados: {presencial.modified_count}")

print("Backfill completado.")
