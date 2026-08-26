###
###
### Utilidades de generación de certificados PDF.
### Función extraída de app.py para evitar circular imports.
###
###
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.pdfgen import canvas
from pdfrw import PdfReader, PdfWriter, PageMerge
import qrcode

from app import collection_eventos, collection_posters, collection_participantes


def generar_pdf_participante(participante, afiche_path, lugar=None):
    codigo_evento = participante['codigo_evento']
    evento = collection_eventos.find_one({"codigo": codigo_evento})

    titulo_evento = evento.get('nombre', 'Título no disponible')
    unidad_evento = evento.get('unidad_ejecutora', 'Unidad ejecutora no disponible')
    carga_horaria_evento = evento.get('carga_horaria', '08')
    fecha_fin_evento = evento.get('fecha_fin')
    fecha_inicio_evento = evento.get('fecha_inicio')
    
    # Convert to date objects for comparison if they're strings
    if isinstance(fecha_inicio_evento, str):
        fecha_inicio_evento = datetime.strptime(fecha_inicio_evento, '%Y-%m-%d %H:%M:%S')
    if isinstance(fecha_fin_evento, str):
        fecha_fin_evento = datetime.strptime(fecha_fin_evento, '%Y-%m-%d %H:%M:%S')
    
    # Format dates based on same/different months and days
    if fecha_inicio_evento.date() == fecha_fin_evento.date():
        # Single day event: "05 de agosto de 2025"
        fecha_fin_formateada = fecha_fin_evento.strftime('%d de %B de %Y')
    elif fecha_inicio_evento.month == fecha_fin_evento.month:
        # Same month: "05 al 06 de agosto de 2025"
        fecha_inicio_formateada = fecha_inicio_evento.strftime('%d')
        fecha_fin_formateada = f"{fecha_inicio_formateada} al {fecha_fin_evento.strftime('%d')} de {fecha_fin_evento.strftime('%B de %Y')}"
    else:
        # Different months: "31 de agosto al 02 de septiembre de 2025"
        fecha_inicio_formateada = fecha_inicio_evento.strftime('%d de %B')
        fecha_fin_formateada = f"{fecha_inicio_formateada} al {fecha_fin_evento.strftime('%d de %B de %Y')}"

    # Definir la ruta donde se guardará el PDF
    pdf_directory = 'static/certificados/'

    if not os.path.exists(pdf_directory):
        os.makedirs(pdf_directory)

    # Nombre del archivo PDF temporal a crear
    temp_pdf_filename = f"temp_{participante['nanoid']}.pdf"
    temp_pdf_path = os.path.join(pdf_directory, temp_pdf_filename)

    c = canvas.Canvas(temp_pdf_path, pagesize=landscape(letter))

    c.setFont("Helvetica", 14)
    #c.setFillColor("black")
    c.setFillColor(HexColor('#002060'))

    page_width = landscape(letter)[0]

    # Escribir los datos del participante centrados en la página
    def draw_centered_text(y_position, text, font="Helvetica", size=12, max_width=None):
        c.setFont(font, size)  # Cambiar fuente y tamaño
        
        # Si no se especifica ancho máximo o el texto cabe en una línea
        if not max_width or c.stringWidth(text, font, size) <= max_width:
            text_width = c.stringWidth(text, font, size)
            x_position = (page_width - text_width) / 2  # Calcular posición X para centrar
            c.drawString(x_position, y_position, text)
            return y_position  # Retornar la posición Y final
        
        # Si el texto es muy largo, dividirlo en múltiples líneas
        words = text.split()
        lines = []
        current_line = ""
        
        for word in words:
            test_line = current_line + (" " if current_line else "") + word
            if c.stringWidth(test_line, font, size) <= max_width:
                current_line = test_line
            else:
                if current_line:
                    lines.append(current_line)
                current_line = word
        
        if current_line:
            lines.append(current_line)
        
        # Dibujar cada línea centrada
        line_height = size * 1.2  # Espaciado entre líneas
        current_y = y_position
        
        for line in lines:
            text_width = c.stringWidth(line, font, size)
            x_position = (page_width - text_width) / 2
            c.drawString(x_position, current_y, line)
            current_y -= line_height
        
        return current_y  # Retornar la posición Y final después de todas las líneas

    draw_centered_text(6 * inch, f"{unidad_evento}", font='Helvetica-Bold', size=15)
    draw_centered_text(5.7 * inch, f"confiere el presente certificado a:")
    draw_centered_text(5.2 * inch, f"{participante['nombres']} {participante['apellidos']}", font="Helvetica-Bold", size=18)
    draw_centered_text(4.8 * inch, f"Cédula: {participante['cedula']}", font="Helvetica-Oblique", size=14)
    
    # Mostrar "concursante" en lugar de "presentador_poster"
    if participante['rol'] == 'presentador_poster':
        rol_mostrar = "concursante"
    elif participante['rol'] == 'jurado_poster':
        rol_mostrar = "jurado"
    else:
        rol_mostrar = participante['rol']

    if participante['rol'] == 'presentador_poster':
        if lugar == 1:
            texto_concurso = "Por obtener el primer lugar en el concurso de trabajos de investigación realizado en:"
        elif lugar == 2:
            texto_concurso = "Por obtener el segundo lugar en el concurso de trabajos de investigación realizado en:"
        elif lugar == 3:
            texto_concurso = "Por obtener el tercer lugar en el concurso de trabajos de investigación realizado en:"
        else:
            texto_concurso = "Por su participación en el concurso de trabajos de investigación realizado en:"
        draw_centered_text(4.4 * inch, texto_concurso)
    elif evento.get('registro_abierto') is True:
        draw_centered_text(4.4 * inch, f"Por aprobar la actividad académica titulada:")
    else:
        draw_centered_text(4.4 * inch, f"Por su asistencia en calidad de {rol_mostrar} en:")
    
    # Usar ancho máximo de 7 pulgadas para el título del evento
    final_y_titulo = draw_centered_text(4 * inch, f"{titulo_evento}", font="Helvetica-Bold", size=14, max_width=9.5 * inch)

    # Ajustar la posición inicial basada en el título del evento con espaciado mínimo consistente
    min_base_y = 4 * inch - 0.5 * inch  # Espaciado mínimo para títulos cortos
    base_y = min(final_y_titulo - 0.2 * inch, min_base_y)
    
    if participante['rol'] == 'ponente':
        ponencia_y = draw_centered_text(base_y, f"Con la ponencia:")
        # Usar ancho máximo de 7 pulgadas para el título de la ponencia
        final_y = draw_centered_text(ponencia_y - 0.3 * inch, f"{participante.get('titulo_ponencia', 'N/A')}", 
                                   font="Helvetica-Bold", size=16, max_width=9.5 * inch)
        # Asegurar un espaciado mínimo consistente
        min_next_y = ponencia_y - 0.9 * inch  # Espaciado mínimo para títulos cortos
        next_y = min(final_y - 0.3 * inch, min_next_y)
    elif participante['rol'] == 'presentador_poster':
        # Buscar el título del póster en la colección de pósters
        poster_data = collection_posters.find_one({
            "codigo_evento": codigo_evento,
            "cedula": participante['cedula']
        })
        titulo_poster = poster_data.get('titulo_poster', 'N/A') if poster_data else 'N/A'
        
        poster_y = draw_centered_text(base_y, f"Con el trabajo de investigación:")
        # Usar ancho máximo de 9.5 pulgadas para el título del póster
        final_y = draw_centered_text(poster_y - 0.3 * inch, f"{titulo_poster}", 
                                   font="Helvetica-Bold", size=16, max_width=9.5 * inch)
        # Asegurar un espaciado mínimo consistente
        min_next_y = poster_y - 0.9 * inch  # Espaciado mínimo para títulos cortos
        next_y = min(final_y - 0.3 * inch, min_next_y)
    elif participante['rol'] == 'participante':
        # --- Prorating logic for participants only ---
        todos_registros = list(collection_participantes.find({
            "cedula": participante['cedula'],
            "codigo_evento": codigo_evento,
            "rol": "participante"
        }))

        registros_validos = []
        for registro in todos_registros:
            if registro.get('indice_registro'):
                try:
                    fecha_registro = datetime.strptime(registro['indice_registro'], '%Y%m%d').date()
                    if fecha_inicio_evento.date() <= fecha_registro <= fecha_fin_evento.date():
                        registros_validos.append(registro)
                except (ValueError, TypeError):
                    continue

        duracion_evento_dias = (fecha_fin_evento.date() - fecha_inicio_evento.date()).days + 1
        texto_horas = "hora" if str(carga_horaria_evento) == "1" else "horas"
        tipo_actividad = "Actividad académica virtual" if evento.get('registro_abierto') is True else "Actividad académica"

        if duracion_evento_dias == 1 or len(registros_validos) == 0:
            actividad_y = draw_centered_text(base_y, f"{tipo_actividad} con una duración de {carga_horaria_evento} {texto_horas}")
            if evento.get('registro_abierto') is not True:
                fecha_y = draw_centered_text(actividad_y - 0.3 * inch, f"Asistencia: {fecha_fin_formateada}")
            else:
                fecha_y = actividad_y
            next_y = fecha_y - 0.3 * inch
        elif len(registros_validos) == 1:
            fecha_asistencia = datetime.strptime(registros_validos[0]['indice_registro'], '%Y%m%d')
            horas_totales = int(carga_horaria_evento)
            horas_por_dia = horas_totales / duracion_evento_dias
            horas_asistencia = round(horas_por_dia)
            horas_texto = "hora" if horas_asistencia == 1 else "horas"

            fecha_asistencia_formateada = fecha_asistencia.strftime('%d de %B de %Y')
            actividad_y = draw_centered_text(base_y, f"{tipo_actividad} con una duración de {horas_asistencia} {horas_texto}")
            fecha_y = draw_centered_text(actividad_y - 0.3 * inch, f"Asistencia: {fecha_asistencia_formateada}")
            next_y = fecha_y - 0.3 * inch
        else:
            fechas_asistencia = []
            for registro in registros_validos:
                if registro.get('indice_registro'):
                    fecha = datetime.strptime(registro['indice_registro'], '%Y%m%d')
                    fechas_asistencia.append(fecha)

            fechas_asistencia.sort()

            horas_totales = int(carga_horaria_evento)
            horas_por_dia = horas_totales / duracion_evento_dias
            horas_asistencia = round(horas_por_dia * len(registros_validos))
            horas_texto = "hora" if horas_asistencia == 1 else "horas"

            if len(registros_validos) == duracion_evento_dias:
                actividad_y = draw_centered_text(base_y, f"{tipo_actividad} con una duración de {carga_horaria_evento} {texto_horas}")
                if evento.get('registro_abierto') is not True:
                    fecha_y = draw_centered_text(actividad_y - 0.3 * inch, f"Asistencia: {fecha_fin_formateada}")
                else:
                    fecha_y = actividad_y
            else:
                actividad_y = draw_centered_text(base_y, f"{tipo_actividad} con una duración de {horas_asistencia} {horas_texto}")

                if fechas_asistencia:
                    primer_mes = fechas_asistencia[0].month
                    mismo_mes = all(f.month == primer_mes for f in fechas_asistencia)
                    if mismo_mes:
                        dias_str = ', '.join(f.strftime('%d') for f in fechas_asistencia[:-1])
                        fecha_texto = f"Asistencia: {dias_str} y {fechas_asistencia[-1].strftime('%d')} de {fechas_asistencia[0].strftime('%B de %Y')}"
                    else:
                        fechas_str = ', '.join(f.strftime('%d de %B') for f in fechas_asistencia[:-1])
                        fecha_texto = f"Asistencia: {fechas_str} y {fechas_asistencia[-1].strftime('%d de %B de %Y')}"
                else:
                    fecha_texto = f"Asistencia: {fecha_fin_formateada}"

                fecha_y = draw_centered_text(actividad_y - 0.3 * inch, fecha_texto, max_width=9.5 * inch)

            next_y = fecha_y - 0.3 * inch
    else:
        texto_horas = "hora" if str(carga_horaria_evento) == "1" else "horas"
        tipo_actividad = "Actividad académica virtual" if evento.get('registro_abierto') is True else "Actividad académica"
        actividad_y = draw_centered_text(base_y, f"{tipo_actividad} con una duración de {carga_horaria_evento} {texto_horas}")

        if evento.get('registro_abierto') is True:
            fecha_y = actividad_y
        else:
            fecha_y = draw_centered_text(actividad_y - 0.3 * inch, fecha_fin_formateada)

        next_y = fecha_y - 0.3 * inch

    # Format just the end date for the 'Dado en...' line
    fecha_fin_simple = fecha_fin_evento.strftime('%d de %B de %Y')
    # Usar next_y si está definido (para ponentes) o la posición fija para participantes
    final_position = next_y if 'next_y' in locals() else 2.7 * inch
    # Determinar la provincia basada en la región
    region = evento.get('region', '')
    if region == 'bocasdeltoro':
        provincia = 'Provincia de Bocas del Toro'
    elif region == 'cocle':
        provincia = 'Provincia de Coclé'
    elif region == 'colon':
        provincia = 'Provincia de Colón'
    elif region == 'chiriqui':
        provincia = 'Provincia de Chiriquí'
    elif region == 'herrera':
        provincia = 'Provincia de Herrera'
    elif region == 'lossantos':
        provincia = 'Provincia de Los Santos'
    elif region == 'veraguas':
        provincia = 'Provincia de Veraguas'
    else:
        provincia = 'Provincia de Panamá'

    if evento.get('registro_abierto') is True:
        draw_centered_text(final_position, f"Dado en la República de Panamá, el {fecha_fin_simple}")
    else:
        draw_centered_text(final_position, f"Dado en la República de Panamá, {provincia}, el {fecha_fin_simple}")

    # Código de certificado en la esquina superior derecha
    c.setFillColor("white")
    c.setFont("Courier", 12)
    nanoid_text = f"ID validación: {participante['nanoid']}"
    text_width = c.stringWidth(nanoid_text, "Courier", 12)
    x_position = page_width - text_width - 0.3 * inch
    c.drawString(x_position, landscape(letter)[1] - 0.3 * inch, nanoid_text)

    # Generar el código QR
    qr_data = participante['nanoid']
    qr_img_path = "static/certificados/qrcode.png"  # Ruta donde se guardará el QR
    qr_img = qrcode.make(qr_data)
    qr_img.save(qr_img_path)

    # Insertar el código QR en el PDF justo debajo del nanoid
    c.drawImage(qr_img_path, x_position - -1.45 * inch, landscape(letter)[1] - 1.5 * inch, width=1 * inch, height=1 * inch)  # Ajusta tamaño y posición según sea necesario

    # Finalizar el nuevo PDF
    c.save()

    os.remove(qr_img_path)

    # Nombre del archivo PDF combinado a crear
    if lugar is not None:
        output_pdf_filename = f"{participante['nanoid']}_podio.pdf"
    else:
        output_pdf_filename = f"{participante['nanoid']}.pdf"
    output_pdf_path = os.path.join(pdf_directory, output_pdf_filename)

    # Leer el PDF de fondo
    background_pdf = PdfReader(afiche_path)
    new_pdf = PdfReader(temp_pdf_path)

    writer = PdfWriter()

    # Combinar las páginas
    for page in range(len(background_pdf.pages)):
        background_page = background_pdf.pages[page]
        new_page = new_pdf.pages[0] if page < len(new_pdf.pages) else None

        if new_page:
            # Combinar la página de fondo con la nueva página
            PageMerge(background_page).add(new_page).render()

        writer.addPage(background_page)

    # Guardar el PDF combinado en la ruta deseada
    writer.write(output_pdf_path)

    # Eliminar el archivo PDF temporal
    os.remove(temp_pdf_path)

    return output_pdf_path  # Retornar la ruta del archivo guardado
