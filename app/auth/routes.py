from flask import Blueprint, request, redirect, url_for, flash, session, render_template
from app.logs import log_event
from app.auth.services import generate_csrf_token
from app.auth import roles_required, UserRole
from flask_login import login_required, current_user

auth_routes_bp = Blueprint('auth_routes', __name__, url_prefix='/')


@auth_routes_bp.route('/iniciar_sesion', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        from app.auth.services import (
            check_user_blocked, 
            check_user_active, 
            validate_user_credentials,
            create_user_session,
            record_failed_login_attempt,
            record_failed_ip_attempt,
            check_ip_blocked,
            validate_csrf_token,
            get_client_ip,
            User
        )
        from flask_login import login_user

        csrf_token = request.form.get('csrf_token', '')
        if not validate_csrf_token(csrf_token):
            flash('Sesión inválida. Intente nuevamente.', 'error')
            return render_template('iniciar_sesion.html', csrf_token=generate_csrf_token())
        
        email = request.form['email']
        password = request.form['password']
        ip_address = get_client_ip()

        is_ip_blocked, ip_blocked_until = check_ip_blocked(ip_address)
        if is_ip_blocked:
            log_event(f"IP [{ip_address}] bloqueada por intentos masivos.")
            flash('Demasiados intentos desde esta dirección IP. Intente más tarde.', 'error')
            return render_template('iniciar_sesion.html', csrf_token=generate_csrf_token())

        is_blocked, blocked_until = check_user_blocked(email)
        if is_blocked:
            log_event(f"Usuario [{email}] intentó ingresar con la cuenta bloqueada temporalmente.")
            flash('Esta cuenta está bloqueada temporalmente. Intente más tarde.', 'error')
            return render_template('iniciar_sesion.html', csrf_token=generate_csrf_token())

        user_data = validate_user_credentials(email, password)

        if user_data:
            is_active = check_user_active(email)
            if not is_active:
                log_event(f"Usuario [{email}] intentó ingresar con una cuenta inactiva.")
                flash('Esta cuenta está inactiva. Contacte al administrador.', 'error')
                return render_template('iniciar_sesion.html', csrf_token=generate_csrf_token())

            session_info = create_user_session(email)
            user = User(
                email=user_data['email'],
                password='',
                rol=user_data['rol'],
                cedula=user_data.get('cedula', ''),
                nombres=user_data.get('nombres', ''),
                apellidos=user_data.get('apellidos', '')
            )
            user.id = user_data['id']
            session.clear()
            login_user(user)
            session.permanent = True
            log_event(f"Usuario [{email}] ingresó exitosamente.")
            return redirect(url_for('tablero_coordinadores'))
        else:
            result = record_failed_login_attempt(email)
            record_failed_ip_attempt(ip_address)
            if result.get('blocked'):
                log_event(f"Usuario [{email}] ha bloqueado la cuenta.")
                flash('Has excedido el número máximo de intentos. La cuenta ha sido bloqueada por 15 minutos.', 'error')
            else:
                log_event(f"Usuario [{email}] intentó ingresar con credenciales incorrectas.")
                flash('Credenciales incorrectas. Inténtalo de nuevo.', 'error')

    return render_template('iniciar_sesion.html', csrf_token=generate_csrf_token())


@auth_routes_bp.route('/salir', methods=['POST'])
def logout():
    from flask_login import logout_user
    logout_user()
    return redirect(url_for('home'))


@auth_routes_bp.route('/tablero/admin/desbloquear-usuarios', methods=['GET', 'POST'])
@login_required
@roles_required(UserRole.ADMINISTRADOR)
def admin_desbloquear_usuarios():
    from app.auth.services import unlock_user, get_blocked_users
    from app import collection_usuarios
    from app.logs import log_event
    from datetime import datetime

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if email:
            success, message = unlock_user(email)
            if success:
                log_event(f"Administrador [{current_user.email}] desbloqueó al usuario [{email}].")
                flash(message, 'success')
            else:
                flash(message, 'error')
        return redirect(url_for('auth_routes.admin_desbloquear_usuarios'))

    blocked_users, unknown_blocked = get_blocked_users()
    
    # Enriquecer datos de usuarios bloqueados
    usuarios_bloqueados = []
    for user in blocked_users:
        blocked_until = user.get('blocked_until')
        tiempo_restante = None
        if blocked_until:
            diff = blocked_until - datetime.utcnow()
            if diff.total_seconds() > 0:
                minutos = int(diff.total_seconds() / 60)
                segundos = int(diff.total_seconds() % 60)
                tiempo_restante = f"{minutos}m {segundos}s"
        
        usuarios_bloqueados.append({
            'email': user.get('email'),
            'nombres': user.get('nombres', ''),
            'apellidos': user.get('apellidos', ''),
            'cedula': user.get('cedula', ''),
            'rol': user.get('rol', ''),
            'failed_attempts': user.get('failed_attempts', 0),
            'blocked_until': blocked_until,
            'tiempo_restante': tiempo_restante
        })
    
    # Usuarios desconocidos (emails no registrados)
    emails_desconocidos = []
    for record in unknown_blocked:
        blocked_until = record.get('blocked_until')
        tiempo_restante = None
        if blocked_until:
            diff = blocked_until - datetime.utcnow()
            if diff.total_seconds() > 0:
                minutos = int(diff.total_seconds() / 60)
                segundos = int(diff.total_seconds() % 60)
                tiempo_restante = f"{minutos}m {segundos}s"
        
        emails_desconocidos.append({
            'email': record.get('unknown_email'),
            'attempts': record.get('attempts', 0),
            'blocked_until': blocked_until,
            'tiempo_restante': tiempo_restante
        })

    return render_template('admin_desbloquear_usuarios.html',
        usuarios_bloqueados=usuarios_bloqueados,
        emails_desconocidos=emails_desconocidos)
