"""Backfill idempotente para LMS jerárquico (Módulo -> Submódulo -> Contenido).

- Solo añade `modulo_id`/`submodulo_id = None` donde no existan ($exists:false).
- Nunca sobrescribe valores ya asignados: re-ejecutable en producción.
- Los cursos planos existentes quedan como huérfanos (modo mixto) y se
  renderizan igual que antes.

Uso dev:
    python scripts/backfill_lms_jerarquia.py [--dry-run]
Uso prod:
    desplegar código primero (tolera campos ausentes), luego ejecutar script.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pymongo import MongoClient  # noqa: E402

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = "certi_css"
DRY_RUN = "--dry-run" in sys.argv


def main():
    client = MongoClient(MONGO_URI)
    col = client[DB_NAME]["eva"]

    total_sin_modulo = col.count_documents({"modulo_id": {"$exists": False}})
    total_sin_sub = col.count_documents({"submodulo_id": {"$exists": False}})
    print(f"[eva] docs sin modulo_id: {total_sin_modulo}, sin submodulo_id: {total_sin_sub}")

    if DRY_RUN:
        print("dry-run: sin cambios.")
        return 0

    r1 = col.update_many(
        {"modulo_id": {"$exists": False}},
        {"$set": {"modulo_id": None}},
    )
    r2 = col.update_many(
        {"submodulo_id": {"$exists": False}},
        {"$set": {"submodulo_id": None}},
    )
    print(f"modificados: modulo_id={r1.modified_count}, submodulo_id={r2.modified_count}")

    # Limpieza defensiva: submódulos legacy no deberían existir, pero si algún
    # doc quedó con tipo desconocido no navegable, se reporta.
    raros = list(col.find({"tipo": {"$nin": ["video", "texto", "documento", "caso_chatgpt", "examen", "modulo", "submodulo"]}}, {"codigo_evento": 1, "orden": 1, "tipo": 1}).limit(20))
    if raros:
        print(f"ADVERTENCIA: {len(raros)} docs con tipo inesperado (muestra):")
        for r in raros:
            print(f"  - {r.get('codigo_evento')} orden={r.get('orden')} tipo={r.get('tipo')!r}")
    else:
        print("Tipos OK: todos los docs usan tipos conocidos.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
