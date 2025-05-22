###
###
###  Script independiente para calcular el nanoid de una exportación de participantes en formato CSV
### 
###  - `generate_nanoid`: Función que genera un nanoid determinístico de 8 caracteres basado en la 
###     cédula, evento y título opcional.
###
###
import csv
import hashlib
import sys

def generate_nanoid(cedula, codigo_evento, titulo_ponencia=None):
    """Genera un nanoid determinístico de 8 caracteres basado en la cédula, evento y título opcional."""
    if titulo_ponencia is None:
        titulo_ponencia = ""
    base_string = f"{cedula}{codigo_evento}{titulo_ponencia}"
    hash_object = hashlib.sha256(base_string.encode())
    return hash_object.hexdigest()[:8]

def main(input_file, output_file):
    with open(input_file, newline='', encoding='utf-8') as csv_in, \
         open(output_file, 'w', newline='', encoding='utf-8') as csv_out:
        
        reader = csv.DictReader(csv_in)
        fieldnames = reader.fieldnames.copy()

        if 'nanoid' not in fieldnames:
            fieldnames.append('nanoid')

        writer = csv.DictWriter(csv_out, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            if not row.get('nanoid'):  # Solo generar si está vacío
                cedula = row.get('cedula', '')
                codigo_evento = row.get('codigo_evento', '')
                titulo_ponencia = row.get('titulo_ponencia', '')  # puede que no exista
                row['nanoid'] = generate_nanoid(cedula, codigo_evento, titulo_ponencia)
            writer.writerow(row)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Uso: python agregar_nanoid.py archivo_entrada.csv archivo_salida.csv")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    main(input_file, output_file)
