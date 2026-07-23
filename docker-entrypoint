#!/bin/bash
set -e

echo "Ejecutando backfill lms_activo..."
python scripts/backfill_lms_activo.py

echo "Iniciando Gunicorn..."
exec gunicorn --bind 0.0.0.0:5000 --workers 2 --timeout 60 wsgi:app
