from locust import HttpUser, task, between

class MiUsuario(HttpUser):
    wait_time = between(1, 5)

    @task
    def visitar_home(self):
        self.client.get("/")

    @task
    def ver_eventos(self):
        self.client.get("/catalogo/1")

    @task
    def ver_nosotros(self):
        self.client.get("/nosotros")

class UsuarioBuscadorCertificados(HttpUser):
    wait_time = between(1, 3)

    @task
    def buscar_certificado(self):
        data = {
            "cedula": ""
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        self.client.post("/buscar_certificados", data=data, headers=headers)