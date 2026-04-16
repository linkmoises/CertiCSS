from flask import Blueprint, request, redirect, url_for, flash, session, render_template
from app.logs import log_event

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
            User
        )
        from flask_login import login_user
        
        email = request.form['email']
        password = request.form['password']

        is_blocked, blocked_until = check_user_blocked(email)
        if is_blocked:
            log_event(f"Usuario [{email}] intentó ingresar con la cuenta bloqueada temporalmente.")
            flash('Esta cuenta está bloqueada temporalmente. Intente más tarde.', 'error')
            return render_template('iniciar_sesion.html')

        user_data = validate_user_credentials(email, password)

        if user_data:
            is_active = check_user_active(email)
            if not is_active:
                log_event(f"Usuario [{email}] intentó ingresar con una cuenta inactiva.")
                flash('Esta cuenta está inactiva. Contacte al administrador.', 'error')
                return render_template('iniciar_sesion.html')

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
            login_user(user)
            session.permanent = True
            log_event(f"Usuario [{email}] ingresó exitosamente.")
            return redirect(url_for('tablero_coordinadores'))
        else:
            result = record_failed_login_attempt(email)
            if result.get('blocked'):
                log_event(f"Usuario [{email}] ha bloqueado la cuenta.")
                flash('Has excedido el número máximo de intentos. La cuenta ha sido bloqueada por 15 minutos.', 'error')
            else:
                log_event(f"Usuario [{email}] intentó ingresar con credenciales incorrectas.")
                flash('Credenciales incorrectas. Inténtalo de nuevo.', 'error')

    return render_template('iniciar_sesion.html')


@auth_routes_bp.route('/salir', methods=['POST'])
def logout():
    from flask_login import logout_user
    logout_user()
    return redirect(url_for('home'))
