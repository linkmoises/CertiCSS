###
###
### Generación del PDF con la lista completa de participantes de un evento.
###
### El documento usa tamaño carta, la plantilla genérica de membrete como fondo
### de página completa y una tabla de 25 filas por página con las columnas
### Nombre, Cédula, Perfil profesional y Unidad ejecutora. La última página
### incluye la nota de fe y el espacio para la firma del creador del evento.
###
###
import io
import os
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.utils import simpleSplit
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, Table, TableStyle

from app.template_selection import parse_event_date

PAGE_WIDTH, PAGE_HEIGHT = letter
FILAS_POR_PAGINA = 25

MARGEN_IZQUIERDO = 45
MARGEN_DERECHO = 45
ANCHO_CONTENIDO = PAGE_WIDTH - MARGEN_IZQUIERDO - MARGEN_DERECHO

# Área útil entre la barra superior y la franja inferior del membrete.
# El margen superior incluye 1 cm adicional de aire bajo el membrete.
MARGEN_SUPERIOR = 78 + 1 * cm
MARGEN_INFERIOR = 52

# Orden de aparición en la lista: organizadores primero y participantes al final.
ORDEN_ROLES = {
    'organizador': 0,
    'coorganizador': 1,
    'ponente': 2,
    'tallerista': 2,
    'instructor': 2,
    'presentador_poster': 2,
    'jurado_poster': 2,
    'apoyo operativo': 3,
    'participante': 4,
}

PERFILES_PROFESIONALES = {
    'medico_general': 'Médico General - Consulta Externa',
    'medico_urgencias': 'Médico General - Urgencias',
    'medico_administrativo': 'Médico Administrativo',
    'medico_especialista': 'Médico Especialista',
    'medico_investigador': 'Médico Investigador',
    'medico_residente': 'Médico Residente',
    'medico_interno': 'Médico Interno',
    'odontologo': 'Odontólogo(a)',
    'odontologo_especialista': 'Odontólogo(a) Especialista',
    'odontologo_interno': 'Odontólogo interno',
    'tao': 'Técnico en asistencia odontológica',
    'enfermera_especialista': 'Enfermera(o) Especializada(o)',
    'enfermero': 'Enfermera(o)',
    'tecnico_enfermeria': 'Técnico en Enfermería',
    'asistente_clinica': 'Asistente Clínica',
    'laboratorista': 'Laboratorista',
    'tecnico_laboratorio': 'Técnico de Laboratorio',
    'farmaceutico': 'Farmacéutico(a)',
    'tecnico_farmacia': 'Técnico de Farmacia',
    'reges': 'Estadístico de Salud',
    'fisioterapeuta': 'Fisioterapeuta',
    'fonoaudiologo': 'Fonoaudiólogo(a)',
    'psicologo': 'Psicólogo(a)',
    'nutricionista': 'Nutricionista',
    'lic_tecnologia_ortopedica': 'Licenciado en Tecnología Ortopédica',
    'estudiante_salud': 'Estudiante',
    'citologo': 'Citólogos',
    'histotecnologo': 'Histotecnólogo',
    'quimico': 'Químico',
    'lic_um': 'Licenciado en Urgencias Médicas y Desastres',
    'tum': 'Técnico en Urgencias Médicas y Desastres',
    'lic_rx': 'Licenciado en Radiología e Imágenes Médicas',
    'tec_rx': 'Técnico en Radiología e Imágenes Médicas',
    'lic_sso': 'Licenciado en Salud y Seguridad Ocupacional',
    'tec_sso': 'Técnico en Salud y Seguridad Ocupacional',
    'lic_tx_so': 'Licenciado en Terapia Ocupacional',
    'ing_so': 'Ingeniero en Salud Ocupacional',
    'higienista': 'Higienista',
    'terapia_respiratoria': 'Terapia Respiratoria',
    'trabajador_social': 'Trabajador Social',
    'administrativo': 'Administrativo',
    'otro': 'Otro',
}

MESES = (
    'enero', 'febrero', 'marzo', 'abril', 'mayo', 'junio',
    'julio', 'agosto', 'septiembre', 'octubre', 'noviembre', 'diciembre',
)

GRIS_NOTA = colors.HexColor('#808080')
GRIS_LINEA = colors.HexColor('#8C8C8C')
AZUL_ENCABEZADO = colors.HexColor('#002060')

MEMBRETE_POR_DEFECTO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'static', 'assets', 'membrete-css-generico.jpg',
)


def _fecha_con_mes(fecha, incluir_anio=True):
    """Formatea una fecha como '05 de agosto de 2025'."""
    if not fecha:
        return ''
    texto = f"{fecha.day:02d} de {MESES[fecha.month - 1]}"
    return f"{texto} de {fecha.year}" if incluir_anio else texto


def formatear_rango_fechas(evento):
    """Rango de fechas del evento en español, con el formato de los certificados."""
    if not isinstance(evento, dict):
        return ''
    inicio = parse_event_date(evento.get('fecha_inicio'))
    fin = parse_event_date(evento.get('fecha_fin')) or inicio
    if not inicio:
        return ''

    if fin and inicio.date() == fin.date():
        return _fecha_con_mes(inicio)
    if fin and inicio.year == fin.year and inicio.month == fin.month:
        return (
            f"{inicio.day:02d} al {fin.day:02d} de "
            f"{MESES[fin.month - 1]} de {fin.year}"
        )
    if fin and inicio.year == fin.year:
        return f"{_fecha_con_mes(inicio, False)} al {_fecha_con_mes(fin)}"
    if fin:
        return f"{_fecha_con_mes(inicio)} al {_fecha_con_mes(fin)}"
    return _fecha_con_mes(inicio)


def etiqueta_perfil(perfil):
    """Traduce el código de perfil profesional a su etiqueta visible."""
    if not perfil:
        return ''
    clave = str(perfil).strip()
    return PERFILES_PROFESIONALES.get(clave, clave.replace('_', ' ').title())


def _clave_orden(participante):
    rol = str(participante.get('rol', '') or '').strip().lower()
    return ORDEN_ROLES.get(rol, 4)


def preparar_participantes(participantes):
    """Ordena y depura la lista: un registro por cédula, de organizador a participante.

    Un mismo funcionario puede tener varios registros en el evento (uno por día
    de asistencia). Para una lista firmada se muestra una sola vez, conservando
    el registro de mayor jerarquía y, dentro de ese grupo, el más reciente.
    """
    ordenados = sorted(
        participantes,
        key=lambda p: (
            _clave_orden(p),
            str(p.get('apellidos', '') or '').lower(),
            str(p.get('nombres', '') or '').lower(),
        ),
    )

    unicos = {}
    for participante in ordenados:
        cedula = str(participante.get('cedula', '') or '').strip()
        clave = cedula or id(participante)
        if clave not in unicos:
            unicos[clave] = participante
    return list(unicos.values())


def _ajustar_texto(texto, fuente, tamano, ancho, max_lineas):
    """Recorta el texto a `max_lineas` con puntos suspensivos si no cabe."""
    texto = str(texto or '').strip()
    if not texto:
        return ''
    lineas = simpleSplit(texto, fuente, tamano, ancho)
    if len(lineas) <= max_lineas:
        return texto

    palabras = texto.split()
    while palabras:
        candidato = ' '.join(palabras) + '...'
        if len(simpleSplit(candidato, fuente, tamano, ancho)) <= max_lineas:
            return candidato
        palabras.pop()
    return '...'


def _dibujar_centrado(c, y, texto, fuente, tamano, color=colors.black,
                      ancho=ANCHO_CONTENIDO, max_lineas=1, interlineado=None):
    """Dibuja texto centrado (posiblemente en varias líneas) y devuelve la nueva Y."""
    if not texto:
        return y
    texto = _ajustar_texto(texto, fuente, tamano, ancho, max_lineas)
    c.setFont(fuente, tamano)
    c.setFillColor(color)
    paso = interlineado or (tamano + 2)
    for linea in simpleSplit(texto, fuente, tamano, ancho):
        c.drawCentredString(PAGE_WIDTH / 2, y, linea)
        y -= paso
    return y


def _dibujar_encabezado(c, evento, y):
    """Dibuja el encabezado (unidad ejecutora, título y fechas) y devuelve la Y final."""
    unidad = str(evento.get('unidad_ejecutora', '') or '').strip()
    titulo = str(evento.get('nombre', '') or '').strip()
    fechas = formatear_rango_fechas(evento)

    y = _dibujar_centrado(c, y, unidad, 'Helvetica-Bold', 11, AZUL_ENCABEZADO,
                          max_lineas=1)
    y = _dibujar_centrado(c, y - 1, titulo, 'Helvetica-Bold', 11,
                          colors.HexColor('#1A1A1A'), max_lineas=2,
                          interlineado=12.5)
    y = _dibujar_centrado(c, y - 1, fechas, 'Helvetica', 9.5,
                          colors.HexColor('#333333'), max_lineas=1)
    return y - 6


def _estilo_celda(negrita=False):
    return ParagraphStyle(
        name='CeldaLista',
        fontName='Helvetica-Bold' if negrita else 'Helvetica',
        fontSize=7.4,
        leading=7.8,
        textColor=colors.HexColor('#111111'),
    )


def _crear_tabla(filas):
    encabezados = ['Nombre', 'Cédula', 'Perfil profesional', 'Unidad ejecutora']
    anchos = [168, 66, 148, 140]
    estilo_encabezado = _estilo_celda(negrita=True)
    estilo_celda = _estilo_celda()

    datos = [[Paragraph(escape(titulo), estilo_encabezado) for titulo in encabezados]]
    for participante in filas:
        nombre = ', '.join(
            parte for parte in (
                str(participante.get('apellidos', '') or '').strip(),
                str(participante.get('nombres', '') or '').strip(),
            ) if parte
        )
        cedula = str(participante.get('cedula', '') or '').strip()
        perfil = etiqueta_perfil(participante.get('perfil'))
        unidad = str(participante.get('unidad', '') or '').strip()

        celdas = []
        for valor, ancho in zip((nombre, cedula, perfil, unidad), anchos):
            texto = _ajustar_texto(valor, 'Helvetica', 7.4, ancho - 8, 2)
            celdas.append(Paragraph(escape(texto), estilo_celda))
        datos.append(celdas)

    tabla = Table(
        datos,
        colWidths=anchos,
        rowHeights=[19] + [18] * len(filas),
    )
    tabla.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E0E0E0')),
        ('GRID', (0, 0), (-1, -1), 0.4, GRIS_LINEA),
        ('BOX', (0, 0), (-1, -1), 0.8, colors.HexColor('#555555')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 1),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
    ]))
    return tabla


def _dibujar_pagina(c, y, indice, total_paginas):
    """Escribe 'Página X de N' justo debajo de la tabla y devuelve la nueva Y."""
    y -= 12
    c.setFont('Helvetica', 8)
    c.setFillColor(colors.HexColor('#404040'))
    c.drawRightString(
        PAGE_WIDTH - MARGEN_DERECHO, y,
        f"Página {indice} de {total_paginas}",
    )
    return y


def _dibujar_nota_y_firma(c, y, nombre_autor, evento_cerrado=False):
    """Dibuja la declaración de fe (gris 50%) y el espacio de firma del organizador.

    Si el evento sigue abierto se advierte antes de la declaración que el
    listado es preliminar y puede cambiar hasta el cierre del evento.
    """
    ancho_nota = ANCHO_CONTENIDO - 10
    y_nota = y - 10

    if not evento_cerrado:
        aviso = (
            "Aviso: el evento se encuentra abierto. Este listado es preliminar "
            "y puede tener modificaciones hasta el cierre del evento dentro de "
            "la plataforma DENADOI-CertiCSS."
        )
        aviso = _ajustar_texto(aviso, 'Helvetica-BoldOblique', 8.5, ancho_nota, 3)
        c.setFont('Helvetica-BoldOblique', 8.5)
        c.setFillColor(colors.HexColor('#555555'))
        for linea in simpleSplit(aviso, 'Helvetica-BoldOblique', 8.5, ancho_nota):
            c.drawString(MARGEN_IZQUIERDO + 4, y_nota, linea)
            y_nota -= 10
        y_nota -= 4

    texto = (
        f"Por medio de la presente, yo, {nombre_autor}, en mi calidad de "
        "responsable de la organización del evento, doy fe de que las personas "
        "incluidas en este listado se encontraban presentes durante el "
        "desarrollo de la actividad docente."
    )
    texto = _ajustar_texto(texto, 'Helvetica', 8.8, ancho_nota, 4)

    c.setFont('Helvetica', 8.8)
    c.setFillColor(GRIS_NOTA)
    for linea in simpleSplit(texto, 'Helvetica', 8.8, ancho_nota):
        c.drawString(MARGEN_IZQUIERDO + 4, y_nota, linea)
        y_nota -= 10.5

    # Espacio en blanco para firmar y raya de firma centrada.
    y_linea = y_nota - 30
    c.setStrokeColor(colors.black)
    c.setLineWidth(0.8)
    ancho_firma = 240
    c.line(
        (PAGE_WIDTH - ancho_firma) / 2, y_linea,
        (PAGE_WIDTH + ancho_firma) / 2, y_linea,
    )
    c.setFillColor(colors.black)
    c.setFont('Helvetica', 9)
    c.drawCentredString(PAGE_WIDTH / 2, y_linea - 13, nombre_autor)


def generar_pdf_lista_participantes(evento, participantes, nombre_autor,
                                    membrete_path=None):
    """Genera el PDF de la lista completa y devuelve sus bytes.

    La lista incluye todos los roles, ordenados de organizador a participante,
    con 25 filas por página. La plantilla de membrete se dibuja como fondo de
    página completa y la última página lleva la nota de fe y la firma.
    """
    membrete_path = membrete_path or MEMBRETE_POR_DEFECTO
    filas = preparar_participantes(participantes or [])

    paginas = [
        filas[inicio:inicio + FILAS_POR_PAGINA]
        for inicio in range(0, len(filas), FILAS_POR_PAGINA)
    ] or [[]]
    total_paginas = len(paginas)

    nombre_autor = str(nombre_autor or '').strip() or '________________'
    evento_cerrado = str(evento.get('estado_evento', '')).strip().lower() == 'cerrado'

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    c.setTitle(f"Lista de participantes - {evento.get('nombre', '')}")

    for indice, grupo in enumerate(paginas, start=1):
        if os.path.exists(membrete_path):
            c.drawImage(
                membrete_path, 0, 0,
                width=PAGE_WIDTH, height=PAGE_HEIGHT,
                preserveAspectRatio=False, mask=None,
            )

        y = PAGE_HEIGHT - MARGEN_SUPERIOR
        y = _dibujar_encabezado(c, evento, y)

        tabla = _crear_tabla(grupo)
        ancho_tabla, alto_tabla = tabla.wrapOn(c, ANCHO_CONTENIDO, y - MARGEN_INFERIOR)
        x_tabla = (PAGE_WIDTH - ancho_tabla) / 2
        tabla.drawOn(c, x_tabla, y - alto_tabla)

        y_despues_tabla = _dibujar_pagina(
            c, y - alto_tabla, indice, total_paginas
        )

        if indice == total_paginas:
            _dibujar_nota_y_firma(
                c, y_despues_tabla, nombre_autor, evento_cerrado
            )

        c.showPage()

    c.save()
    return buffer.getvalue()
