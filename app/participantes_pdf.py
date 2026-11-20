###
###
### Generación del PDF con la lista de participantes de un evento.
###
### El documento usa tamaño carta, la plantilla genérica de membrete como fondo
### de página completa y una tabla con las columnas Nombre, Cédula, Perfil
### profesional y Unidad ejecutora. Un evento de una sola jornada produce una
### lista única; un evento de varios días separa el documento en bloques por
### día, repitiendo en cada bloque al organizador y al equipo organizador y
### cerrando con la declaración de fe y la firma del creador del evento.
###
###
import io
import os
from datetime import datetime, timedelta
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

# Cada fila de datos mide 17pt y cada etiqueta de grupo 15pt. El presupuesto
# de un día de un evento de una sola jornada es el de la lista actual
# (25 filas); cuando el documento separa jornadas, el título del día consume
# el espacio equivalente a dos filas para que la declaración de fe siga
# cabiendo en la última página de cada bloque.
ALTO_FILA = 17
ALTO_SECCION = 15
ALTO_TITULO_DIA = 14
PRESUPUESTO_PAGINA = FILAS_POR_PAGINA * ALTO_FILA
PRESUPUESTO_PAGINA_CON_DIA = PRESUPUESTO_PAGINA - 2 * ALTO_FILA

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

ETIQUETA_RESPONSABLE = 'Responsable de la actividad'
ETIQUETA_EQUIPO = 'Equipo organizador'

# Grupos visibles en cada jornada, en el orden en que se imprimen.
ETIQUETA_ORGANIZADORES = 'Organizador y equipo organizador'
ETIQUETA_EXPOSITORES = 'Expositores'
ETIQUETA_PARTICIPANTES = 'Participantes'

GRUPOS_JORNADA = (
    ('organizadores', ETIQUETA_ORGANIZADORES),
    ('expositores', ETIQUETA_EXPOSITORES),
    ('participantes', ETIQUETA_PARTICIPANTES),
)

ROLES_ORGANIZACION = frozenset({'organizador', 'coorganizador', 'apoyo operativo'})
ROLES_EXPOSITORES = frozenset({
    'ponente', 'tallerista', 'instructor', 'presentador_poster',
})
# Roles que se registran una sola vez para todo el evento y, por lo tanto,
# deben repetirse en la lista de cada jornada.
ROLES_EVENTO_COMPLETO = ROLES_ORGANIZACION | frozenset({
    'presentador_poster', 'jurado_poster',
})

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
    if clave in (ETIQUETA_RESPONSABLE, ETIQUETA_EQUIPO):
        return clave
    return PERFILES_PROFESIONALES.get(clave, clave.replace('_', ' ').title())


def _clave_orden(participante):
    rol = str(participante.get('rol', '') or '').strip().lower()
    return ORDEN_ROLES.get(rol, 4)


def preparar_participantes(participantes):
    """Ordena y deduplica una lista: un registro por cédula.

    Dentro de una misma jornada y grupo un funcionario puede tener varios
    registros; se conserva el de mayor jerarquía y, dentro de ese grupo, el
    primero por apellidos. La separación por jornadas se hace antes, en
    `preparar_listas_por_dia`.
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


def dias_del_evento(evento):
    """Días del evento como fechas, de inicio a fin."""
    if not isinstance(evento, dict):
        return []
    inicio = parse_event_date(evento.get('fecha_inicio'))
    if not inicio:
        return []

    fin = parse_event_date(evento.get('fecha_fin')) or inicio
    if fin.date() < inicio.date():
        fin = inicio

    dias = []
    actual = inicio.date()
    ultimo = fin.date()
    # Los eventos académicos no duran años; el límite evita que una fecha
    # errónea en la base de datos genere miles de páginas.
    while actual <= ultimo and len(dias) < 366:
        dias.append(actual)
        actual += timedelta(days=1)
    return dias


def _rol(participante):
    return str(participante.get('rol', '') or '').strip().lower()


def _grupo_de(rol):
    if rol in ROLES_ORGANIZACION:
        return 'organizadores'
    if rol in ROLES_EXPOSITORES:
        return 'expositores'
    return 'participantes'


def _dia_de_registro(participante):
    """Día al que pertenece un registro, según los campos que guarda el sistema."""
    fecha = str(participante.get('fecha_evento', '') or '').strip()
    if fecha:
        try:
            return datetime.strptime(fecha[:10], '%Y-%m-%d').date()
        except ValueError:
            pass

    marca = participante.get('fecha_checkin')
    if isinstance(marca, datetime):
        return marca.date()

    indice = str(participante.get('indice_registro', '') or '').strip()
    if len(indice) == 8 and indice.isdigit():
        try:
            return datetime.strptime(indice, '%Y%m%d').date()
        except ValueError:
            pass

    marca = participante.get('timestamp')
    if isinstance(marca, datetime):
        return marca.date()
    if isinstance(marca, str) and marca.strip():
        try:
            return datetime.fromisoformat(marca.replace('Z', '+00:00')).date()
        except ValueError:
            return None
    return None


def preparar_listas_por_dia(evento, participantes):
    """Agrupa los registros por jornada y por grupo.

    Devuelve ``[(dia, [(etiqueta, filas), ...]), ...]`` en orden cronológico.
    Los organizadores y demás roles que se registran una sola vez para todo el
    evento se repiten en cada jornada; expositores y participantes aparecen
    únicamente en el día de su registro, usando la fecha del evento, la de
    check-in o el índice de registro. Un registro con fecha fuera del rango se
    lista en la jornada más cercana. Dentro de cada jornada una persona figura
    una sola vez, en el grupo de mayor jerarquía.
    """
    dias = dias_del_evento(evento)
    base = dias or [None]
    por_dia = {
        dia: {nombre: [] for nombre, _ in GRUPOS_JORNADA} for dia in base
    }

    for participante in participantes or []:
        if not isinstance(participante, dict):
            continue
        rol = _rol(participante)
        grupo = _grupo_de(rol)
        dia = _dia_de_registro(participante)

        if rol in ROLES_EVENTO_COMPLETO:
            destinos = base
        elif dias:
            # Un registro fuera del rango del evento (por ejemplo, la fecha de
            # preinscripción) se lista en la jornada más cercana.
            if dia is None or dia < dias[0]:
                destino = dias[0]
            elif dia > dias[-1]:
                destino = dias[-1]
            else:
                destino = dia
            destinos = [destino]
        else:
            destinos = [None]

        for destino in destinos:
            por_dia[destino][grupo].append(participante)

    secciones = []
    for dia in base:
        vistos = set()
        grupos = []
        for nombre, etiqueta in GRUPOS_JORNADA:
            filas = []
            for participante in preparar_participantes(por_dia[dia][nombre]):
                cedula = str(participante.get('cedula', '') or '').strip()
                clave = cedula or id(participante)
                if clave in vistos:
                    continue
                vistos.add(clave)
                filas.append(participante)
            if filas:
                grupos.append((etiqueta, aplicar_etiquetas_organizacion(filas)))
        if grupos:
            secciones.append((dia, grupos))

    if secciones:
        return secciones
    return [(dias[0] if dias else None, [])]


def aplicar_etiquetas_organizacion(participantes):
    """Etiqueta el perfil de organizadores y coorganizadores.

    El organizador figura como responsable de la actividad y los
    coorganizadores como equipo organizador, sin importar el perfil que
    tuvieran registrado. Devuelve copias para no modificar los datos originales.
    """
    etiquetados = []
    for participante in participantes:
        rol = str(participante.get('rol', '') or '').strip().lower()
        copia = dict(participante)
        if rol == 'organizador':
            copia['perfil'] = ETIQUETA_RESPONSABLE
        elif rol == 'coorganizador':
            copia['perfil'] = ETIQUETA_EQUIPO
        etiquetados.append(copia)
    return etiquetados


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


def _estilo_seccion():
    return ParagraphStyle(
        name='EtiquetaGrupo',
        fontName='Helvetica-Bold',
        fontSize=7.6,
        leading=8,
        textColor=colors.HexColor('#002060'),
    )


def _items_de_grupos(grupos, con_etiquetas=False):
    """Convierte los grupos de una jornada en filas y etiquetas de tabla.

    En un evento de una sola jornada se mantiene el formato compacto sin
    etiquetas; al separar por días cada grupo se identifica con su etiqueta.
    """
    items = []
    for etiqueta, filas in grupos:
        if not filas:
            continue
        if con_etiquetas:
            items.append(('seccion', etiqueta))
        items.extend(('fila', participante) for participante in filas)
    return items


def _paginar_items(items, presupuesto):
    """Reparte las filas en páginas respetando el alto disponible.

    Una etiqueta de grupo nunca queda sola al final de una página.
    """
    paginas = []
    actual = []
    usado = 0

    for posicion, item in enumerate(items):
        alto = ALTO_SECCION if item[0] == 'seccion' else ALTO_FILA
        necesario = alto
        if item[0] == 'seccion' and posicion + 1 < len(items):
            necesario += ALTO_FILA

        if actual and usado + necesario > presupuesto:
            paginas.append(actual)
            actual = []
            usado = 0

        actual.append(item)
        usado += alto

    if actual or not paginas:
        paginas.append(actual)
    return paginas


def _crear_tabla(items):
    encabezados = ['Nombre', 'Cédula', 'Perfil profesional', 'Unidad ejecutora']
    anchos = [168, 66, 148, 140]
    estilo_encabezado = _estilo_celda(negrita=True)
    estilo_celda = _estilo_celda()
    estilo_seccion = _estilo_seccion()

    datos = [[Paragraph(escape(titulo), estilo_encabezado) for titulo in encabezados]]
    alturas = [19]
    filas_seccion = []

    for tipo, valor in items:
        if tipo == 'seccion':
            datos.append([Paragraph(escape(valor), estilo_seccion), '', '', ''])
            alturas.append(ALTO_SECCION)
            filas_seccion.append(len(datos) - 1)
            continue

        participante = valor
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
        for texto_valor, ancho in zip((nombre, cedula, perfil, unidad), anchos):
            texto = _ajustar_texto(texto_valor, 'Helvetica', 7.4, ancho - 8, 2)
            celdas.append(Paragraph(escape(texto), estilo_celda))
        datos.append(celdas)
        alturas.append(ALTO_FILA)

    tabla = Table(datos, colWidths=anchos, rowHeights=alturas)
    estilos = [
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E0E0E0')),
        ('GRID', (0, 0), (-1, -1), 0.4, GRIS_LINEA),
        ('BOX', (0, 0), (-1, -1), 0.8, colors.HexColor('#555555')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 0.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0.5),
    ]
    for fila in filas_seccion:
        estilos.append(('SPAN', (0, fila), (-1, fila)))
        estilos.append(('BACKGROUND', (0, fila), (-1, fila), colors.HexColor('#F2F2F2')))
    tabla.setStyle(TableStyle(estilos))
    return tabla


def _dibujar_pagina(c, y, indice, total_paginas):
    """Escribe 'Página X de N' justo debajo de la tabla y devuelve la nueva Y."""
    y -= 10
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
    y_nota = y - 20

    if not evento_cerrado:
        aviso = (
            "Aviso: el evento está abierto; este listado es preliminar y puede "
            "cambiar hasta su cierre en la plataforma DENADOI-CertiCSS."
        )
        aviso = _ajustar_texto(aviso, 'Helvetica-BoldOblique', 8.5, ancho_nota, 3)
        c.setFont('Helvetica-BoldOblique', 8.5)
        c.setFillColor(colors.HexColor('#555555'))
        for linea in simpleSplit(aviso, 'Helvetica-BoldOblique', 8.5, ancho_nota):
            c.drawString(MARGEN_IZQUIERDO + 4, y_nota, linea)
            y_nota -= 10
        y_nota -= 6

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
    y_linea = y_nota - 24
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


def _dibujar_titulo_dia(c, y, dia):
    """Escribe la jornada a la que pertenece la página y devuelve la nueva Y."""
    texto = f"Asistencia del {_fecha_con_mes(dia)}"
    c.setFont('Helvetica-Bold', 10.5)
    c.setFillColor(colors.HexColor('#1A1A1A'))
    c.drawCentredString(PAGE_WIDTH / 2, y, texto)
    return y - ALTO_TITULO_DIA


def generar_pdf_lista_participantes(evento, participantes, nombre_autor,
                                    membrete_path=None):
    """Genera el PDF de la lista de participantes y devuelve sus bytes.

    Los eventos de una sola jornada producen una lista única. Los eventos de
    varios días separan el documento en bloques por día: en cada bloque se
    repite el organizador y el equipo organizador, se listan los expositores y
    participantes de ese día, se pagina "Página X de N" dentro del bloque y se
    cierra con la declaración de fe y la firma del responsable.

    La plantilla de membrete se dibuja como fondo de página completa.
    """
    membrete_path = membrete_path or MEMBRETE_POR_DEFECTO
    secciones = preparar_listas_por_dia(evento, participantes or [])
    separar_dias = len(dias_del_evento(evento)) > 1 or len(secciones) > 1

    nombre_autor = str(nombre_autor or '').strip() or '________________'
    evento_cerrado = str(evento.get('estado_evento', '')).strip().lower() == 'cerrado'
    presupuesto = (
        PRESUPUESTO_PAGINA_CON_DIA if separar_dias else PRESUPUESTO_PAGINA
    )

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    c.setTitle(f"Lista de participantes - {evento.get('nombre', '')}")

    for dia, grupos in secciones:
        paginas = _paginar_items(
            _items_de_grupos(grupos, separar_dias), presupuesto
        )
        total_paginas = len(paginas)

        for indice, items in enumerate(paginas, start=1):
            if os.path.exists(membrete_path):
                c.drawImage(
                    membrete_path, 0, 0,
                    width=PAGE_WIDTH, height=PAGE_HEIGHT,
                    preserveAspectRatio=False, mask=None,
                )

            y = PAGE_HEIGHT - MARGEN_SUPERIOR
            y = _dibujar_encabezado(c, evento, y)
            if separar_dias and dia is not None:
                y = _dibujar_titulo_dia(c, y, dia)

            tabla = _crear_tabla(items)
            ancho_tabla, alto_tabla = tabla.wrapOn(
                c, ANCHO_CONTENIDO, y - MARGEN_INFERIOR
            )
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
