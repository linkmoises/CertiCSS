# Sistema de Permisos Granulares

## Descripción

Este sistema permite asignar permisos específicos a usuarios sin modificar su rol base. Es útil cuando usuarios de roles inferiores necesitan acceso a secciones específicas (como LMS) sin cambiar su jerarquía.

## Permisos Disponibles

| Permiso ID | Nombre | Descripción |
|------------|--------|-------------|
| `lms_admin` | LMS Admin | Crear y editar contenidos LMS |
| `lms_view` | LMS Ver | Ver contenidos LMS (para instructores) |
| `qbanks_admin` | Qbanks Admin | Gestionar bancos de preguntas |
| `metricas_avanzadas` | Métricas Avanzadas | Ver métricas detalladas del sistema |
| `exportar_datos` | Exportar Datos | Exportar bases de datos |
| `gestionar_usuarios` | Gestionar Usuarios | Crear y editar usuarios |

## Instalación

### 1. Migrar Base de Datos

Ejecuta el script de migración para agregar el campo `permisos` a todos los usuarios existentes:

```bash
# En desarrollo local
python migrar-permisos.py

# En Docker
docker exec -it certicss python migrar-permisos.py
```

### 2. Verificar Instalación

Accede como administrador a:
- **Ruta:** `/tablero/roles-permisos`
- **Menú:** Administración → Roles y permisos

## Uso

### Para Administradores

1. Accede a **Administración → Roles y permisos**
2. Verás una tabla con todos los usuarios (excepto administradores)
3. Marca los checkboxes de los permisos que deseas otorgar
4. Los cambios se guardan automáticamente al marcar/desmarcar

### Estructura en MongoDB

```javascript
{
  "_id": ObjectId("..."),
  "email": "usuario@ejemplo.com",
  "rol": "coordinador-local",  // Rol base (no cambia)
  "permisos": ["lms_admin", "lms_view"],  // Permisos adicionales
  "nombres": "Juan",
  "apellidos": "Pérez",
  // ... otros campos
}
```

## Implementación Técnica

### Clase User (app.py)

La clase `User` ahora incluye:

```python
class User(UserMixin):
    def __init__(self, ..., permisos=None):
        self.permisos = permisos if permisos is not None else []
    
    def has_permission(self, permission):
        """Verifica si tiene un permiso específico"""
        if self.is_admin():
            return True
        return permission in self.permisos
    
    def has_any_permission(self, *permissions):
        """Verifica si tiene al menos uno de los permisos"""
        if self.is_admin():
            return True
        return any(permission in self.permisos for permission in permissions)
```

### Decorador de Permisos (app/auth.py)

```python
from app.auth import permission_required

@app.route('/ruta-protegida')
@login_required
@permission_required('lms_admin', 'lms_view')  # Requiere al menos uno
def mi_ruta():
    # Solo usuarios con lms_admin O lms_view pueden acceder
    pass
```

**Nota:** Los administradores siempre tienen acceso a todas las rutas protegidas.

### Verificación Manual en Vistas

```python
@app.route('/mi-ruta')
@login_required
def mi_ruta():
    if not current_user.has_permission('lms_admin'):
        abort(403)
    
    # O verificar múltiples permisos
    if not current_user.has_any_permission('lms_admin', 'lms_view'):
        abort(403)
    
    # Código de la ruta...
```

### En Templates

```jinja2
{% if current_user.has_permission('lms_admin') %}
    <a href="{{ url_for('crear_contenido') }}">Crear Contenido</a>
{% endif %}

{% if current_user.has_any_permission('lms_admin', 'lms_view') %}
    <a href="{{ url_for('ver_contenidos') }}">Ver Contenidos</a>
{% endif %}
```

## Ejemplos de Uso

### Caso 1: Coordinador Local con Acceso a LMS

```python
# Usuario en MongoDB
{
  "rol": "coordinador-local",
  "permisos": ["lms_admin", "lms_view"]
}
```

Este usuario puede:
- ✓ Crear y editar contenidos LMS
- ✓ Ver contenidos LMS
- ✗ Gestionar bancos de preguntas (no tiene el permiso)
- ✗ Exportar datos (no tiene el permiso)

### Caso 2: Coordinador Departamental sin Permisos Adicionales

```python
# Usuario en MongoDB
{
  "rol": "coordinador-departamental",
  "permisos": []
}
```

Este usuario solo tiene acceso a las funciones de su rol base.

## Próximos Pasos (Pendientes)

1. **Aplicar decoradores a rutas del LMS:**
   ```python
   # En app/plataforma.py
   @plataforma_bp.route("/tablero/eventos/<codigo_evento>/lms")
   @login_required
   @permission_required('lms_admin', 'lms_view')
   def listar_contenidos(codigo_evento):
       ...
   ```

2. **Actualizar templates para mostrar/ocultar opciones según permisos**

3. **Agregar logs de auditoría para cambios de permisos**

4. **Crear interfaz para gestionar permisos en lote**

## Ventajas del Sistema

- ✓ **No modifica roles existentes:** La jerarquía se mantiene intacta
- ✓ **Granularidad total:** Control preciso sobre cada funcionalidad
- ✓ **Fácil de auditar:** Se ve claramente qué permisos tiene cada usuario
- ✓ **Escalable:** Agregar nuevos permisos es trivial
- ✓ **Retrocompatible:** Usuarios sin permisos funcionan normalmente

## Soporte

Para dudas o problemas, contacta al equipo de desarrollo.
