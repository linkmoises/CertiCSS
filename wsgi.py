import sys
import os

# Asegurar que app.py (módulo raíz) se cargue, no el paquete app/
sys.path.insert(0, os.path.dirname(__file__))

# Importar directamente desde app.py usando importlib
import importlib.util
spec = importlib.util.spec_from_file_location("main_app", os.path.join(os.path.dirname(__file__), "app.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

app = module.app
