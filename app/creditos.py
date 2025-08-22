from flask import Blueprint, render_template
from flask_login import login_required

creditos_bp = Blueprint('creditos', __name__)


###
### Créditos de aplicación
###
@creditos_bp.route('/tablero/acerca-de')
@login_required
def creditos():
    return render_template('acerca-de.html')


###
### Marco Legal
###
@creditos_bp.route('/tablero/marco-legal')
@login_required
def marco_legal():
    return render_template('marco-legal.html')
