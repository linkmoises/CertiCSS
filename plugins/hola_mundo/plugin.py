###
### Plugin Hola Mundo
###
### Permite añadir plugins y extender funcionalidad de CertiCSS.
###
### Autor: Moises Serrano Samudio
### Fecha: 2025-12-02
###
### Es posible usar plantillas independientes en los plugins, para ello se debe
### especificar la carpeta de plantillas en el Blueprint y añadir la ruta de la
### plantilla en el Blueprint.
###
### Ejemplo:
###
### from flask import Blueprint, render_template
###
### bp = Blueprint("hola_mundo", __name__, template_folder="templates")
###
### @bp.route("/hola-mundo")
### def hola_mundo():
###     return render_template("hola_mundo.html")
###
### plugin_api.register_blueprint(bp)
###
###
from flask import Blueprint

def init_plugin(plugin_api):
    bp = Blueprint("hola_mundo", __name__)

    @bp.route("/hola-mundo")
    def hola_mundo():
        return {"mensaje": "Hola Mundo!!!"}

    plugin_api.register_blueprint(bp)
