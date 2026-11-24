#!/usr/bin/env python
"""Rellena examen_id/tarea_id en calificaciones históricas del LMS.

Los registros históricos se enlazan por orden, que cambia al reordenar
contenidos. Este script los enlaza por título (coincidencia única) para que
dejen de depender del orden.

Uso:
    python scripts/backfill_lms_fks.py                      # ensayo, todos los eventos
    python scripts/backfill_lms_fks.py --evento EVT001      # ensayo, un evento
    python scripts/backfill_lms_fks.py --apply              # escribe
    python scripts/backfill_lms_fks.py --evento EVT001 --apply

En producción, ejecutar dentro del contenedor web:

    docker compose exec -T web python scripts/backfill_lms_fks.py
    docker compose exec -T web python scripts/backfill_lms_fks.py --apply

Antes de --apply conviene un respaldo de exam_results y tarea_entregas.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.mantenimiento_lms import backfill_enlaces_lms  # noqa: E402


def main():
    parser = argparse.ArgumentParser(
        description="Rellena el enlace estable de calificaciones históricas del LMS."
    )
    parser.add_argument("--evento", help="Código de evento a procesar")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Escribe cambios (sin este flag solo informa)",
    )
    args = parser.parse_args()

    reporte = backfill_enlaces_lms(
        codigo_evento=args.evento, aplicar=args.apply
    )
    print(json.dumps(reporte, ensure_ascii=False, indent=2, default=str))

    pendientes = sum(
        len(detalle["ambiguos"])
        + len(detalle["sin_coincidencia"])
        + len(detalle["sin_titulo"])
        for detalle in reporte.values()
    )
    actualizados = sum(
        detalle["actualizados"] for detalle in reporte.values()
    )
    modo = "APPLY" if args.apply else "DRY-RUN"
    print(
        f"\nModo {modo}: actualizados={actualizados} "
        f"sin_resolver={pendientes}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
