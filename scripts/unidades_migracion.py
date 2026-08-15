#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
###
###  Migración y siembra de la colección centralizada 'unidades'
###
###  Modos:
###    --report                 Compara la colección contra el seed y muestra:
###                             - unidades del seed ausentes en la colección
###                             - unidades en la colección que no están en el seed (revisión)
###                             - candidatas a San Miguelito mal clasificadas
###                             - documentos sin categoria/region
###    --admin-seed             Upsert por nombre de las unidades administrativas
###                             (categoria=administrativa, region=administrativas,
###                              region_usuario=css00)
###    --dev-seed               Siembra unidades físicas/regionales (unión de templates)
###                             + unidades administrativas. Solo inserta las que faltan.
###    --backfill-san-miguelito Asigna region=sanmiguelito / region_usuario=css088 a
###                             unidades cuyo nombre está en SAN_MIGUELITO_UNITS.
###    --dry-run                No escribe nada; imprime lo que haría.
###
###  Uso:
###    python scripts/unidades_migracion.py --report
###    python scripts/unidades_migracion.py --dev-seed --dry-run
###    python scripts/unidades_migracion.py --admin-seed
###    python scripts/unidades_migracion.py --backfill-san-miguelito --dry-run
###
###
import argparse
import os
import re
import sys
import unicodedata
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pymongo import MongoClient
from config import config
from app.unidades_data import (
    PROVINCIA_A_REGION,
    REGION_A_CSS,
    SAN_MIGUELITO_UNITS,
    invalidar_cache_unidades,
)

DB_NAME = 'certi_css'

SEED_FISICAS = {
    'panama': [
        'CAPPS Los Nogales',
        'CAPPS Pedregal',
        'CAPPS Plaza Tocumen',
        'Centro Nacional Especializado de la Salud y Seguridad de los Trabajadores Dr. Francisco Díaz Mérida',
        'Ciudad De La Salud',
        'Complejo Hospitalario Metropolitano Dr. Arnulfo Arias Madrid',
        'Hospital de Especialidades Pediátricas Omar Torrijos Herrera',
        'Policlínica Don Alejandro De La Guardia Hijo',
        'Policlínica Don Joaquín José Vallarino',
        'Policlínica Dr. Carlos N. Brin',
        'Policlínica Dr. Manuel Ferrer Valdés',
        'Policlínica Presidente Remón',
        'ULAPS Máximo Herrera',
        'ULAPS Prof. Carlos Velarde',
    ],
    'sanmiguelito': [
        'CAPPS Torrijos Carter',
        'Hospital Dra. Susana Jones Cano',
        'Policlínica Don Generoso Guardia',
        'Policlínica Dr. Edilberto Culiolis',
        'Policlínica Dra. Cecilia Guerra',
        'Policlínica Lic. Manuel María Valdés',
    ],
    'panamaoeste': [
        'CAPPS Capira',
        'CAPPS El Tecal',
        'CAPPS Vacamonte',
        'Coordinación Regional - Panamá Oeste',
        'Coordinación Regional de Docencia - Panamá Oeste',
        'Hospital Hogar de La Esperanza',
        'Policlínica Dr. Blas Gómez Chetro',
        'Policlínica Dr. Juan Vega Méndez',
        'Policlínica Dr. Santiago Barraza',
        'ULAPS El Tecal',
        'ULAPS Guadalupe',
        'ULAPS San José',
        'ULAPS Sra. Lastenia Cano Solís',
        'ULAPS Vista Alegre',
        'ULSYSO Dr. Luis Salvatierra Tello',
    ],
    'panamaeste': [
        'CAPPS Los Nogales',
        'Coordinación Regional - Panamá Este',
        'Coordinación Regional de Docencia - Panamá Este',
        'Hospital Irma de Lourdes Tzanetatos',
        'Hospital Regional de Chepo',
        'Policlínica de Cañitas',
    ],
    'bocasdeltoro': [
        'Coordinación Regional - Bocas Del Toro',
        'Coordinación Regional - Bocas del Toro',
        'Coordinación Regional de Docencia - Bocas Del Toro',
        'Hospital Regional Dr. Raúl Dávila Mena',
        'Hospital Regional de Almirante',
        'Hospital Regional de Changuinola',
        'Hospital de Chiriquí Grande',
        'Policlínica de Guabito',
        'ULAPS Juan Aguilar',
        'ULAPS Las Tablas',
    ],
    'cocle': [
        'CAPPS La Pintada',
        'Coordinación Regional - Coclé',
        'Coordinación Regional de Docencia - Coclé',
        'Hospital Regional Dr. Rafael Estévez',
        'Policlínica Dr. Manuel De Jesús Rojas',
        'Policlínica Dr. Manuel Paulino Ocaña',
        'Policlínica San Juan De Dios',
    ],
    'colon': [
        'Complejo Hospitalario Dr. Manuel Amador Guerrero',
        'Coordinación Regional - Colón',
        'Coordinación Regional de Docencia - Colón',
        'Policlínica Dr. Hugo Spadafora',
        'Policlínica de Nuevo San Juan',
        'Policlínica de Sabanitas',
        'ULAPS Portobelo',
    ],
    'chiriqui': [
        'CAPPS',
        'CAPPS Balsa',
        'CAPPS Barú',
        'CAPPS Blanco',
        'CAPPS Caoba',
        'CAPPS Corredor',
        'CAPPS Jobito',
        'CAPPS Zapatero',
        'Coordinación Regional - Chiriquí',
        'Coordinación Regional de Docencia - Chiriquí',
        'Hospital Dr. Dionisio Arrocha',
        'Hospital Regional Dr. Rafael Hernández',
        'Policlínica Dr. Ernesto Perez Balladares',
        'Policlínica Dr. Gustavo Adolfo Ross',
        'Policlínica Dr. Pablo Espinosa',
        'Policlínica Dr. Rodrigo Hidalgo',
        'Policlínica de Divalá',
        'ULAPS Carlos Alvarado',
        'ULAPS Dolega',
        'ULAPS Faustino Fonseca',
        'ULAPS Nuevo Vedado',
        'ULAPS Volcán',
    ],
    'herrera': [
        'CAPPS Los Pozos',
        'CAPPS Ocú',
        'CAPPS Pesé',
        'Coordinación Regional - Herrera',
        'Coordinación Regional de Docencia - Herrera',
        'Hospital Dr. Gustavo Nelson Collado',
        'Policlínica Dr. Roberto Ramírez De Diego',
    ],
    'lossantos': [
        'CAPPS Guararé',
        'CAPPS Macaracas',
        'CAPPS Tonosí',
        'Coordinación Regional - Los Santos',
        'Coordinación Regional de Docencia - Los Santos',
        'Policlínica Dr. Miguel Cárdenas Barahona',
        'Policlínica San Juan de Dios',
    ],
    'veraguas': [
        'CAPPS Zapotillo',
        'Coordinación Regional - Veraguas',
        'Coordinación Regional de Docencia - Veraguas',
        'Hospital Dr. Ezequiel Abadía',
        'Policlínica Dr. Horacio Díaz Gómez',
        'ULAPS Alberto León',
    ],
}

SEED_ADMIN = [
    'Centro Institucional de Farmacovigilancia',
    'Centro de Simulación Avanzada',
    'Comisión Institucional de Farmacoterapia',
    'Coordinación Nacional de Bioseguridad',
    'Coordinación Nacional de Clínica de Curaciones de Heridas, Úlceras y Pie Diabético',
    'Coordinación Nacional de Infecciones Nosocomiales',
    'Coordinación Nacional de Terapia Respiratoria',
    'Coordinación Nacional de Terapias de Sustitución Renal y Enfermedad Crónica de los Riñones',
    'Coordinación Nacional de los Servicios de Urgencias',
    'Departamento Nacional de Docencia e Investigación',
    'Departamento Nacional de Farmacia',
    'Departamento Nacional de Fisioterapia',
    'Departamento Nacional de Gestión en Emergencias, Desastres y Transporte de Pacientes',
    'Departamento Nacional de Nutrición',
    'Departamento Nacional de Odontología',
    'Departamento Nacional de Planificación de Salud',
    'Departamento Nacional de Trabajo Social',
    'Dirección Nacional de Salud y Seguridad Ocupacional',
    'Programa Materno Infantil',
    'Programa Nacional de Alto Riesgo Neonatal',
    'Programa Nacional de Jubilados, Pensionados, Tercera Edad y SADI',
    'Programa Nacional de Medicina Familiar',
    'Programa Nacional de Tuberculosis',
    'Programa de Salud de Adultos',
    'Subdirección Nacional de Atención Primaria en Salud',
]

REGION_LABEL = {
    'panama': 'Panamá Metro',
    'sanmiguelito': 'San Miguelito',
    'panamaoeste': 'Panamá Oeste',
    'panamaeste': 'Panamá Este',
    'bocasdeltoro': 'Bocas del Toro',
    'cocle': 'Coclé',
    'colon': 'Colón',
    'chiriqui': 'Chiriquí',
    'herrera': 'Herrera',
    'lossantos': 'Los Santos',
    'veraguas': 'Veraguas',
    'administrativas': 'Administrativas',
}

REGION_A_PROVINCIA = {v: k for k, v in PROVINCIA_A_REGION.items()}

TIPO_NIVELES = {
    'Coordinación Regional': (5, 'NA'),
    'Hospital de Referencia Nacional': (4, 3),
    'Hospital de Alta Complejidad': (4, 3),
    'Hospital Regional': (4, 2),
    'Hospital General': (4, 1),
    'Policlínica Especializada': (3, 3),
    'Policlínica Básica': (3, 2),
    'CAPPS': (2, 1),
    'ULAPS': (2, 1),
    'ULSySO': (2, 1),
}


def slugify(nombre):
    texto = unicodedata.normalize('NFKD', nombre)
    texto = ''.join(c for c in texto if not unicodedata.combining(c))
    texto = re.sub(r'[^a-zA-Z0-9]+', '-', texto.lower()).strip('-')
    return texto or 'unidad'


def inferir_tipo_fisico(nombre):
    if nombre.startswith('Coordinación Regional'):
        return 'Coordinación Regional'
    if 'Complejo Hospitalario' in nombre or nombre == 'Ciudad De La Salud':
        return 'Hospital de Referencia Nacional'
    if 'Hospital de Especialidades' in nombre:
        return 'Hospital de Alta Complejidad'
    if 'Hospital Regional' in nombre:
        return 'Hospital Regional'
    if 'Hospital' in nombre:
        return 'Hospital General'
    if 'Policlínica' in nombre:
        return 'Policlínica Especializada'
    if 'ULSYSO' in nombre:
        return 'ULSySO'
    if 'ULAPS' in nombre:
        return 'ULAPS'
    if 'CAPPS' in nombre:
        return 'CAPPS'
    return 'Hospital General'


def inferir_tipo_admin(nombre):
    if nombre.startswith(('Dirección', 'Subdirección')):
        return 'Dirección'
    if nombre.startswith('Departamento'):
        return 'Departamento'
    if nombre.startswith('Coordinación'):
        return 'Coordinación'
    if nombre.startswith('Programa'):
        return 'Programa'
    if nombre.startswith('Centro'):
        return 'Centro'
    if nombre.startswith('Comisión'):
        return 'Comisión'
    return 'Otra'


def documento_fisico(nombre, region):
    tipo = inferir_tipo_fisico(nombre)
    nivel_asistencial, nivel_complejidad = TIPO_NIVELES[tipo]
    provincia = 'Panamá' if region == 'sanmiguelito' else REGION_A_PROVINCIA.get(region, 'Panamá')
    return {
        'nombre': nombre,
        'slug': slugify(nombre),
        'tipo': tipo,
        'provincia': provincia,
        'categoria': 'regional' if tipo == 'Coordinación Regional' else 'asistencial',
        'region': region,
        'region_usuario': REGION_A_CSS.get(region, 'css00'),
        'nivel_asistencial': nivel_asistencial,
        'nivel_complejidad': nivel_complejidad,
        'formador_internos': False,
        'formador_residente': False,
        'activo': True,
        'timestamp': datetime.now(),
    }


def documento_admin(nombre):
    return {
        'nombre': nombre,
        'slug': slugify(nombre),
        'tipo': inferir_tipo_admin(nombre),
        'categoria': 'administrativa',
        'region': 'administrativas',
        'region_usuario': 'css00',
        'activo': True,
        'timestamp': datetime.now(),
    }


def normalizar(texto):
    texto = unicodedata.normalize('NFKD', texto or '')
    texto = ''.join(c for c in texto if not unicodedata.combining(c))
    return re.sub(r'[^a-z0-9]', '', texto.lower())


def modo_report(col):
    total = col.count_documents({})
    print('=' * 70)
    print('REPORTE de unidades centralizadas')
    print(f'Colección "unidades" en db "{DB_NAME}": {total} documentos')
    print('=' * 70)

    print('\n[Por categoría]')
    for d in col.aggregate([{'$group': {'_id': '$categoria', 'n': {'$sum': 1}}}]):
        print(f'  {d["_id"]}: {d["n"]}')

    print('\n[Por región]')
    for d in col.aggregate([{'$group': {'_id': '$region', 'n': {'$sum': 1}}}]):
        print(f'  {REGION_LABEL.get(d["_id"], d["_id"])} ({d["_id"]}): {d["n"]}')

    en_db = {d['nombre'] for d in col.find({}, {'nombre': 1})}

    print('\n[Ausentes en la colección (candidatas a seed)]')
    fisicas = []
    for region, nombres in SEED_FISICAS.items():
        for nombre in nombres:
            if nombre not in en_db:
                fisicas.append((region, nombre))
    for region, nombre in fisicas:
        print(f'  [{REGION_LABEL.get(region, region)}] {nombre}')
    admin_ausentes = [n for n in SEED_ADMIN if n not in en_db]
    for nombre in admin_ausentes:
        print(f'  [Administrativas] {nombre}')
    if not fisicas and not admin_ausentes:
        print('  (ninguna)')

    seed_set = set(n for nombres in SEED_FISICAS.values() for n in nombres) | set(SEED_ADMIN)
    extra = sorted(en_db - seed_set)
    print('\n[En la colección pero NO en el seed (revisión manual)]')
    if extra:
        for nombre in extra:
            print(f'  {nombre}')
    else:
        print('  (ninguna)')

    norm_seed = {normalizar(n): n for n in seed_set}
    similares = []
    for nombre in sorted(en_db - seed_set):
        clave = normalizar(nombre)
        if clave in norm_seed and norm_seed[clave] != nombre:
            similares.append((nombre, norm_seed[clave]))
    if similares:
        print('\n[Posibles duplicados por normalización (mismo nombre, distinta forma)]')
        for nombre, seed_name in similares:
            print(f'  "{nombre}"  ~  "{seed_name}"')

    print('\n[Candidatas a San Miguelito (nombre conocido con otra región)]')
    candidatas = col.find({'nombre': {'$in': list(SAN_MIGUELITO_UNITS)}})
    any_c = False
    for d in candidatas:
        region = d.get('region')
        if region != 'sanmiguelito':
            any_c = True
            print(f'  {d["nombre"]}: region={region} (debería ser sanmiguelito)')
    if not any_c:
        print('  (ninguna)')

    print('\n[Unidades con provincia "Panamá" (revisión manual San Miguelito / Panamá Metro)]')
    con_panama = list(col.find({'provincia': 'Panamá'}, {'nombre': 1, 'region': 1}))
    if con_panama:
        for d in con_panama:
            marca = '<-- San Miguelito' if d['nombre'] in SAN_MIGUELITO_UNITS else ''
            print(f'  {d["nombre"]}: region={d.get("region")} {marca}')
    else:
        print('  (ninguna)')

    print('\n[Documentos sin categoria o sin region]')
    faltan = col.count_documents({'$or': [{'categoria': {'$exists': False}}, {'region': {'$exists': False}}]})
    print(f'  {faltan} documento(s)')


def modo_admin_seed(col, dry_run):
    print('Upsert por nombre de unidades administrativas' + (' (DRY-RUN)' if dry_run else ''))
    inserts = updates = 0
    for nombre in SEED_ADMIN:
        doc = documento_admin(nombre)
        existente = col.find_one({'nombre': nombre})
        if dry_run:
            estado = 'insertar' if not existente else 'actualizar'
            print(f'  [{estado}] {nombre}')
            inserts += not existente
            updates += bool(existente)
            continue
        resultado = col.update_one(
            {'nombre': nombre},
            {
                '$set': {
                    'tipo': doc['tipo'],
                    'categoria': 'administrativa',
                    'region': 'administrativas',
                    'region_usuario': 'css00',
                    'activo': True,
                    'timestamp_updated': datetime.now(),
                },
                '$setOnInsert': {
                    'slug': doc['slug'],
                    'timestamp': doc['timestamp'],
                },
            },
            upsert=True,
        )
        if resultado.upserted_id:
            inserts += 1
            print(f'  [insertar] {nombre}')
        else:
            updates += 1
            print(f'  [actualizar] {nombre}')
    print(f'\nResumen: {inserts} insertadas, {updates} actualizadas')
    if not dry_run:
        invalidar_cache_unidades()


def modo_dev_seed(col, dry_run):
    print('Siembra dev de unidades físicas/regionales (unión de templates)')
    print(' + unidades administrativas' + (' (DRY-RUN)' if dry_run else ''))
    insertadas = existentes = 0
    for region, nombres in SEED_FISICAS.items():
        for nombre in nombres:
            doc = documento_fisico(nombre, region)
            existe = col.find_one({'nombre': nombre})
            if dry_run:
                print(f'  [{"insertar" if not existe else "omitir (ya existe)"}] [{REGION_LABEL.get(region, region)}] {nombre}')
                insertadas += not existe
                existentes += bool(existe)
                continue
            if not existe:
                col.insert_one(doc)
                insertadas += 1
                print(f'  [insertar] [{REGION_LABEL.get(region, region)}] {nombre}')
            else:
                existentes += 1
                print(f'  [omitir (ya existe)] [{REGION_LABEL.get(region, region)}] {nombre}')
    print()
    print(f'Resumen físicas: {insertadas} insertadas, {existentes} ya existentes')
    print()
    modo_admin_seed(col, dry_run)


def modo_backfill(col, dry_run):
    print('Backfill San Miguelito (region=sanmiguelito, region_usuario=css088)'
          + (' (DRY-RUN)' if dry_run else ''))
    a_cambiar = 0
    for d in col.find({'nombre': {'$in': list(SAN_MIGUELITO_UNITS)}}):
        if d.get('region') == 'sanmiguelito':
            continue
        a_cambiar += 1
        print(f'  [{d["nombre"]}] region={d.get("region")} -> sanmiguelito')
        if not dry_run:
            col.update_one({'_id': d['_id']}, {'$set': {
                'region': 'sanmiguelito',
                'region_usuario': 'css088',
                'timestamp_updated': datetime.now(),
            }})
    print(f'\nResumen: {a_cambiar} unidad(es) recategorizada(s)')
    if not dry_run and a_cambiar:
        invalidar_cache_unidades()


def main():
    parser = argparse.ArgumentParser(description='Migración/siembra de la colección centralizada "unidades".')
    parser.add_argument('--report', action='store_true', help='Compara la colección contra el seed y muestra el estado.')
    parser.add_argument('--admin-seed', action='store_true', help='Upsert de unidades administrativas.')
    parser.add_argument('--dev-seed', action='store_true', help='Siembra unidades físicas/regionales + administrativas.')
    parser.add_argument('--backfill-san-miguelito', action='store_true', help='Recategoriza unidades de San Miguelito.')
    parser.add_argument('--dry-run', action='store_true', help='Solo imprime lo que haría, sin escribir.')
    args = parser.parse_args()

    if not any([args.report, args.admin_seed, args.dev_seed, args.backfill_san_miguelito]):
        parser.print_help()
        sys.exit(1)

    client = MongoClient(os.getenv('MONGO_URI', config.MONGO_URI))
    col = client[DB_NAME]['unidades']

    if args.report:
        modo_report(col)
    if args.admin_seed:
        modo_admin_seed(col, args.dry_run)
    if args.dev_seed:
        modo_dev_seed(col, args.dry_run)
    if args.backfill_san_miguelito:
        modo_backfill(col, args.dry_run)

    client.close()


if __name__ == '__main__':
    main()
