# CertiCSS

¡Hola! 👋 Este proyecto es una aplicación web diseñada específicamente para el **Departamento Nacional de Docencia e Investigación** de la Caja de Seguro Social en Panamá. Su objetivo es facilitar la gestión de eventos académicos, permitiendo registrar participantes, ponentes, crear eventos y subir imágenes asociadas a cada uno. Está construida con Flask y MongoDB, y es súper fácil de usar. 😊

![CertiCSS](screenshot.jpg)

<div style="border: 2px solid red; background-color: #ffe6e6; padding: 15px; border-radius: 5px; margin: 20px 0;">
  <h2 style="color: #cc0000; margin-top: 0;">⚠️ Refactorización en curso</h2>
  <p><strong>Estado actual:</strong> Refactorización arquitectónica en progreso.</p>
  <p>CertiCSS se encuentra en un proceso de <strong>refactorización modular continua</strong>. Los objetivos son:</p>
  <ul>
    <li>Mejorar mantenibilidad: descomponer el monolito en módulos lógicos</li>
    <li>Facilitar testing y auditoría de seguridad por secciones</li>
    <li>Preparar la base de código para escalabilidad futura</li>
  </ul>
  <p><strong>Impacto en usuarios finales:</strong> Ninguno. Solo cambios internos.</p>
</div>

## ¿Qué se puede hacer con CertiCSS?

- **Crear Eventos**: Define eventos con detalles como nombre, tipo, fechas, etc.
- **Registrar Participantes**: Los usuarios pueden inscribirse en eventos específicos.
- **Registrar Ponentes**: Los coordinadores locales de docencia pueden agregar ponentes con el título de su ponencia.
- **Evitar Duplicados**: La aplicación evita que los participantes se registren múltiples veces en el mismo evento y genera códigos únicos para verificar certificados.

## ¿Qué tecnologías usa?

- **Flask**: Un framework ligero y poderoso para construir aplicaciones web en Python.
- **MongoDB**: Una base de datos NoSQL que almacena toda la información de eventos, participantes y ponentes.
- **Tailwind**: Un framework CSS que hace que las interfaces se vean geniales sin complicaciones.

## ¿Cómo empezar?

### Opción 1: Instalación Local (para desarrollo)

Si quieres probar la aplicación en tu máquina, sigue estos pasos:

1. **Clona este repositorio**:
```
git clone https://github.com/linkmoises/CertiCSS.git
cd CertiCSS
```

2. **Crea un entorno virtual** (opcional pero recomendado):
```
python -m venv venv
source venv/bin/activate
```

3. **Instala las dependencias**:
```
pip install -r requirements.txt
```

4. **Asegúrate de tener MongoDB instalado y en ejecución**. Si no lo tienes, puedes instalarlo siguiendo [estas instrucciones](https://www.mongodb.com/docs/manual/installation/).

5. **Crear el usuario administrador** (solo es necesario realizar la primera vez):
```
python install.py
```

8. Después de esta instalación del usuario administrador, podrás continuar corriendo la aplicacion con el comando:
```
chmod +x run-local.sh
./run-local.sh
```
o puedes ejecutar directamente la aplicación:
```
python app.py
```

9. **¡Listo!** Abre tu navegador y ve a `http://localhost:5000` para empezar a usar CertiCSS.


#### Estructura de Archivos de Instalación

- `install-minimal.py` - Configuración básica de base de datos
- `install-deps.sh` - Instalación gradual de dependencias
- `setup-local.sh` - Script completo de instalación
- `run-local.sh` - Script para ejecutar la aplicación

#### Próximos Pasos

1. Accede a http://localhost:5000
2. Inicia sesión con las credenciales de administrador que creaste
3. Ve a "Opciones" para cargar la planilla de funcionarios (opcional)
4. Comienza a crear eventos y gestionar certificados

#### Notas Importantes

- La aplicación se ejecuta en modo desarrollo (DEBUG=True)
- MongoDB debe estar ejecutándose antes de iniciar la aplicación
- El primer usuario creado tendrá rol de administrador
- La base de datos de funcionarios estará vacía inicialmente (normal)

### Opción 2: Usar Docker (para producción o pruebas rápidas)

Si prefieres no instalar nada en tu máquina o quieres probar la aplicación en un entorno aislado, ¡Docker es tu mejor amigo! 🐳

1. **Clona el repositorio** (si no lo has hecho):
```
git clone https://github.com/linkmoises/CertiCSS.git
cd CertiCSS
```

2. **Crea un archivo `.env`**:

- Copia el archivo `.env.example` y renómbralo a `.env`.
- Edita el archivo `.env` para configurar las variables de entorno necesarias (como la SECRET_KEY).

3. **Levanta los contenedores**:

Ejecuta el siguiente comando para construir y levantar la aplicación con Docker:
```
chmod +x run-docker.sh
./run-docker.sh
```

4. **¡Eso es todo!** La aplicación estará disponible en `http://localhost:5000`, MongoDB estará corriendo en segundo plano y ya podrás usar CertiCSS.

## ¿Quieres contribuir? ¡Genial! 🚀

Si te gusta este proyecto y quieres aportar, ¡estás más que bienvenido! Así es como puedes hacerlo:

1. Haz un fork del repositorio.
2. Crea una nueva rama (`git checkout -b feature/nueva-caracteristica`).
3. Realiza tus cambios y haz commit (`git commit -m 'Añadir nueva característica'`).
4. Haz push a la rama (`git push origin feature/nueva-caracteristica`).
5. Abre un Pull Request y cuéntame qué has hecho. ¡Estare encantado de revisarlo!

## Licencia

Este proyecto está bajo la Licencia AGPL v3. Eso significa que puedes usarlo, modificarlo y distribuirlo libremente, pero si haces cambios, debes compartirlos con la comunidad. ¡Compartir es vivir! 😄

Consulta el archivo [LICENSE](LICENSE) para más detalles.

## ¿Tienes preguntas o sugerencias?

Puedes contactarme en [moserrano@css.gob.pa] o abrir un issue en el repositorio. ¡Estoy aquí para ayudar! 🙌

**¡Gracias por usar CertiCSS!** Espero que te sea útil y que disfrutes gestionando tus eventos académicos. 💪