###
###
###  Este archivo contiene las rutas y funciones relacionadas con la carga de  
###  plugins externos
### 
###
###
class PluginAPI:
    def __init__(self, app):
        self.app = app

    def register_blueprint(self, blueprint, url_prefix=None):
        self.app.register_blueprint(blueprint, url_prefix=url_prefix)

