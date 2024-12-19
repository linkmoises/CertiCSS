# CertiCSS

Este proyecto es una aplicación web diseñada específicamente para el Departamento Nacional de Docencia e Investigación de la Caja de Seguro Social en Panamá, para la gestión de eventos académicos. Permite registrar participantes y ponentes, crear eventos y subir imágenes asociadas a cada evento. La aplicación está construida utilizando Flask y MongoDB.

![CertiCSS](screenshot.png)

## Características

- **Registro de Eventos**: Permite crear eventos con información como nombre, tipo, fechas.
- **Registro de Participantes**: Los usuarios pueden registrarse como participantes en eventos específicos.
- **Registro de Ponentes**: Los coordinadores locales de docencia u organizadores pueden registrar a los ponentes, incluyendo el título de su ponencia.
- **Prevención de Duplicados**: Implementa mecanismos para evitar que los participantes se registren múltiples veces en el mismo evento y asigna códigos únicos para verificación de certificados.

## Tecnologías Utilizadas

- **Flask**: Microframework para Python utilizado para construir la aplicación web.
- **MongoDB**: Base de datos NoSQL utilizada para almacenar la información de eventos, participantes y ponentes.
- **HTML/CSS**: Para la creación de las interfaces de usuario.

## Requisitos Previos

Asegúrate de tener instalados los siguientes requisitos:

- Python 3.x
- MongoDB
- pip (gestor de paquetes de Python)

## Instalación

1. Clona este repositorio:
```
git clone https://github.com/linkmoises/CertiCSS.git
cd CertiCSS
```

2. Crea un entorno virtual (opcional pero recomendado):
```
python -m venv venv
source venv/bin/activate
```

3. Instala las dependencias:
```
pip install -r requirements.txt
```

4. Configura tu base de datos MongoDB y asegúrate de que esté en ejecución.

5. Ejecuta la aplicación:
```
python app.py
```

6. Abre tu navegador y ve a `http://localhost:5000` para acceder a la aplicación.

## Uso

1. **Crear un Evento**: Accede a la página de creación de eventos y completa el formulario.
2. **Registrar Participantes**: Una vez creado un evento, puedes registrar participantes proporcionando su información.
3. **Registrar Ponentes**: También puedes registrar ponentes asociados a un evento específico.
4. **Ver Listados**: Puedes ver listas de eventos, participantes y ponentes registrados.

## Contribuciones

Las contribuciones son bienvenidas. Si deseas contribuir a este proyecto, por favor sigue estos pasos:

1. Haz un fork del repositorio.
2. Crea una nueva rama (`git checkout -b feature/nueva-caracteristica`).
3. Realiza tus cambios y haz commit (`git commit -m 'Añadir nueva característica'`).
4. Haz push a la rama (`git push origin feature/nueva-caracteristica`).
5. Abre un Pull Request.

## Licencia

Este proyecto está bajo la Licencia MIT - consulta el archivo [LICENSE](LICENSE) para más detalles.

## Contacto

Si tienes alguna pregunta o sugerencia, no dudes en contactarme en [moserrano@css.gob.pa].