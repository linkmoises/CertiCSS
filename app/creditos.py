from flask import Blueprint, render_template

creditos_bp = Blueprint('creditos', __name__)


###
### Créditos de aplicación
###
@creditos_bp.route('/tablero/acerca-de')
def creditos():
    return render_template('acerca-de.html') 