import csv
import io
import qrcode
import base64
from io import BytesIO
from bson import ObjectId
from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, Response, jsonify, abort
)
from flask_login import login_required, current_user
from app.votacion.services import (
    init_votacion_services, crear_votacion, obtener_votacion_por_codigo,
    obtener_votaciones_por_creador, actualizar_votacion, cerrar_votacion,
    eliminar_votacion, registrar_voto, contar_votos_por_opcion,
    obtener_respuestas, ya_voto
)
from app.helpers import sanitize_html
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

votacion_bp = Blueprint('votacion', __name__)


def _es_creador_o_admin(votacion):
    if not votacion:
        return False
    return (
        current_user.rol == 'administrador'
        or current_user.rol == 'denadoi'
        or votacion.get('creador') == str(current_user.id)
    )


def _generar_qr_base64(url):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    return base64.b64encode(buffer.getvalue()).decode()


@votacion_bp.route('/tablero/votaciones')
@login_required
def lista_votaciones():
    votaciones = obtener_votaciones_por_creador(str(current_user.id))
    for v in votaciones:
        v['total_votos'] = len(obtener_respuestas(v['codigo']))
    return render_template('votacion_lista.html', votaciones=votaciones)


@votacion_bp.route('/votacion/crear', methods=['GET', 'POST'])
@login_required
def crear():
    if request.method == 'POST':
        titulo = request.form.get('titulo', '').strip()
        descripcion = request.form.get('descripcion', '').strip()
        tipo_pregunta = request.form.get('tipo_pregunta', 'opcion_multiple')

        if not titulo:
            flash('El titulo es obligatorio.', 'danger')
            return render_template('votacion_crear.html', editando=False)

        opciones_raw = request.form.getlist('opciones[]')
        opciones = []
        for i, op in enumerate(opciones_raw):
            texto = op.strip()
            if texto:
                opciones.append({'texto': texto, 'orden': i})

        if tipo_pregunta == 'si_no':
            opciones = [
                {'texto': 'Si', 'orden': 0},
                {'texto': 'No', 'orden': 1},
            ]
        elif tipo_pregunta == 'mixta':
            if not opciones:
                opciones = [
                    {'texto': 'Si', 'orden': 0},
                    {'texto': 'No', 'orden': 1},
                ]
        else:
            if len(opciones) < 2:
                flash('Agrega al menos 2 opciones.', 'danger')
                return render_template('votacion_crear.html', editando=False)

        votacion = crear_votacion(titulo, descripcion, tipo_pregunta, opciones, current_user.id)
        flash('Votacion creada exitosamente.', 'success')
        return redirect(url_for('votacion.panel', codigo=votacion['codigo']))

    return render_template('votacion_crear.html', editando=False)


@votacion_bp.route('/votacion/<codigo>/editar', methods=['GET', 'POST'])
@login_required
def editar(codigo):
    votacion = obtener_votacion_por_codigo(codigo)
    if not votacion:
        abort(404)
    if not _es_creador_o_admin(votacion):
        abort(403)

    if request.method == 'POST':
        titulo = request.form.get('titulo', '').strip()
        descripcion = request.form.get('descripcion', '').strip()
        if not titulo:
            flash('El titulo es obligatorio.', 'danger')
            return render_template('votacion_crear.html', votacion=votacion, editando=True)

        opciones_raw = request.form.getlist('opciones[]')
        opciones = []
        for i, op in enumerate(opciones_raw):
            texto = op.strip()
            if texto:
                opciones.append({'texto': texto, 'orden': i})

        tipo = votacion.get('tipo_pregunta', 'opcion_multiple')
        if tipo == 'si_no':
            opciones = [
                {'texto': 'Si', 'orden': 0},
                {'texto': 'No', 'orden': 1},
            ]
        elif tipo == 'mixta':
            if not opciones:
                opciones = [
                    {'texto': 'Si', 'orden': 0},
                    {'texto': 'No', 'orden': 1},
                ]

        actualizar_votacion(codigo, {
            'titulo': titulo,
            'descripcion': descripcion,
            'opciones': opciones,
        })
        flash('Votacion actualizada.', 'success')
        return redirect(url_for('votacion.panel', codigo=codigo))

    return render_template('votacion_crear.html', votacion=votacion, editando=True)


@votacion_bp.route('/votacion/<codigo>/panel')
@login_required
def panel(codigo):
    votacion = obtener_votacion_por_codigo(codigo)
    if not votacion:
        abort(404)
    if not _es_creador_o_admin(votacion):
        abort(403)

    from app import BASE_URL
    url_votar = url_for('votacion.votar', codigo=codigo, _external=True)
    qr_base64 = _generar_qr_base64(url_votar)
    opciones_conteo, total = contar_votos_por_opcion(codigo)

    return render_template('votacion_panel.html',
                           votacion=votacion,
                           qr_base64=qr_base64,
                           url_votar=url_votar,
                           opciones_conteo=opciones_conteo,
                           total_votos=total)


@votacion_bp.route('/votacion/<codigo>/cerrar', methods=['POST'])
@login_required
def cerrar(codigo):
    votacion = obtener_votacion_por_codigo(codigo)
    if not votacion:
        abort(404)
    if not _es_creador_o_admin(votacion):
        abort(403)
    cerrar_votacion(codigo)
    flash('Votacion cerrada.', 'success')
    return redirect(url_for('votacion.panel', codigo=codigo))


@votacion_bp.route('/votacion/<codigo>/reabrir', methods=['POST'])
@login_required
def reabrir(codigo):
    votacion = obtener_votacion_por_codigo(codigo)
    if not votacion:
        abort(404)
    if not _es_creador_o_admin(votacion):
        abort(403)
    actualizar_votacion(codigo, {'estado': 'abierta'})
    flash('Votacion reabierta.', 'success')
    return redirect(url_for('votacion.panel', codigo=codigo))


@votacion_bp.route('/votacion/<codigo>/eliminar', methods=['POST'])
@login_required
def eliminar(codigo):
    votacion = obtener_votacion_por_codigo(codigo)
    if not votacion:
        abort(404)
    if not _es_creador_o_admin(votacion):
        abort(403)
    eliminar_votacion(codigo)
    flash('Votacion eliminada.', 'success')
    return redirect(url_for('votacion.lista_votaciones'))


@votacion_bp.route('/votacion/<codigo>/votar', methods=['GET', 'POST'])
def votar(codigo):
    votacion = obtener_votacion_por_codigo(codigo)
    if not votacion:
        abort(404)

    ya_voto_flag = False
    error_msg = None
    success_msg = None

    if request.method == 'POST':
        if votacion.get('estado') != 'abierta':
            error_msg = 'Esta votacion ya esta cerrada.'
        else:
            nombre = request.form.get('nombre', '').strip()
            cedula = request.form.get('cedula', '').strip()
            opcion = request.form.get('opcion', '').strip()

            if not nombre or len(nombre) < 2:
                error_msg = 'Ingresa tu nombre completo.'
            elif not cedula:
                error_msg = 'Ingresa tu cedula.'
            elif not opcion:
                error_msg = 'Selecciona una opcion.'

            if not error_msg:
                if ya_voto(codigo, cedula):
                    ya_voto_flag = True
                    error_msg = 'Ya has participado en esta votacion.'
                else:
                    ok, msg = registrar_voto(codigo, cedula, sanitize_html(nombre), sanitize_html(opcion))
                    if ok:
                        success_msg = 'Tu voto ha sido registrado. Gracias por participar!'
                    else:
                        error_msg = msg

    return render_template('votacion_votar.html',
                           votacion=votacion,
                           ya_voto=ya_voto_flag,
                           error_msg=error_msg,
                           success_msg=success_msg)


@votacion_bp.route('/api/votacion/<codigo>/resultados')
def api_resultados(codigo):
    votacion = obtener_votacion_por_codigo(codigo)
    if not votacion:
        return jsonify({'error': 'Votacion no encontrada'}), 404

    opciones_conteo, total = contar_votos_por_opcion(codigo)
    resultados = []
    for texto, conteo in opciones_conteo.items():
        pct = round((conteo / total * 100), 1) if total > 0 else 0
        resultados.append({
            'opcion': texto,
            'votos': conteo,
            'porcentaje': pct,
        })

    return jsonify({
        'codigo': codigo,
        'titulo': votacion['titulo'],
        'estado': votacion.get('estado', 'abierta'),
        'total_votos': total,
        'resultados': resultados,
    })


@votacion_bp.route('/votacion/<codigo>/resultados')
def resultados(codigo):
    votacion = obtener_votacion_por_codigo(codigo)
    if not votacion:
        abort(404)

    opciones_conteo, total = contar_votos_por_opcion(codigo)
    return render_template('votacion_resultados.html',
                           votacion=votacion,
                           opciones_conteo=opciones_conteo,
                           total_votos=total)


@votacion_bp.route('/votacion/<codigo>/descargar/csv')
@login_required
def descargar_csv(codigo):
    votacion = obtener_votacion_por_codigo(codigo)
    if not votacion:
        abort(404)
    if not _es_creador_o_admin(votacion):
        abort(403)

    respuestas = obtener_respuestas(codigo)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Fecha', 'Cedula', 'Nombre', 'Opcion Elegida'])
    for r in respuestas:
        fecha = r.get('fecha', '')
        if hasattr(fecha, 'strftime'):
            fecha = fecha.strftime('%Y-%m-%d %H:%M:%S')
        writer.writerow([
            fecha,
            r.get('cedula', ''),
            r.get('nombre', ''),
            r.get('opcion_elegida', ''),
        ])

    output.seek(0)
    filename = f"votacion_{codigo}.csv"
    return Response(
        output.getvalue().encode('utf-8-sig'),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename={filename}',
            'Content-Type': 'text/csv; charset=utf-8',
        }
    )


@votacion_bp.route('/votacion/<codigo>/descargar/pdf')
@login_required
def descargar_pdf(codigo):
    votacion = obtener_votacion_por_codigo(codigo)
    if not votacion:
        abort(404)
    if not _es_creador_o_admin(votacion):
        abort(403)

    respuestas = obtener_respuestas(codigo)
    opciones_conteo, total = contar_votos_por_opcion(codigo)

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                            topMargin=0.75*inch, bottomMargin=0.75*inch,
                            leftMargin=0.75*inch, rightMargin=0.75*inch)
    styles = getSampleStyleSheet()
    elements = []

    title_style = styles['Title']
    elements.append(Paragraph(f"Resultados: {votacion['titulo']}", title_style))
    elements.append(Spacer(1, 0.3*inch))

    subtitle_style = styles['Heading2']
    elements.append(Paragraph(f"Total de votos: {total}", subtitle_style))
    elements.append(Spacer(1, 0.2*inch))

    resumen_data = [['Opcion', 'Votos', 'Porcentaje']]
    for texto, conteo in opciones_conteo.items():
        pct = round((conteo / total * 100), 1) if total > 0 else 0
        resumen_data.append([texto, str(conteo), f"{pct}%"])

    t = Table(resumen_data, colWidths=[3*inch, 1.2*inch, 1.2*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a56db')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f3f4f6')]),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 0.4*inch))

    elements.append(Paragraph("Detalle de participantes", subtitle_style))
    elements.append(Spacer(1, 0.15*inch))

    detalle_data = [['Fecha', 'Cedula', 'Nombre', 'Opcion']]
    for r in respuestas:
        fecha = r.get('fecha', '')
        if hasattr(fecha, 'strftime'):
            fecha = fecha.strftime('%d/%m/%Y %H:%M')
        detalle_data.append([
            str(fecha),
            r.get('cedula', ''),
            r.get('nombre', ''),
            r.get('opcion_elegida', ''),
        ])

    t2 = Table(detalle_data, colWidths=[1.6*inch, 1.2*inch, 1.8*inch, 1.6*inch])
    t2.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a56db')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('TOPPADDING', (0, 0), (-1, 0), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f3f4f6')]),
    ]))
    elements.append(t2)

    doc.build(elements)
    buffer.seek(0)

    filename = f"votacion_{codigo}.pdf"
    return Response(
        buffer.getvalue(),
        mimetype='application/pdf',
        headers={
            'Content-Disposition': f'attachment; filename={filename}',
        }
    )
