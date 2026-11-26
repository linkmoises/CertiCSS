"""Utilidades de texto enriquecido para la mensajería interna.

El editor del navegador produce HTML; aquí se normaliza a un subconjunto
seguro de etiquetas antes de guardarlo y mostrarlo. También se deriva una
versión en texto plano para las vistas previas de las bandejas.
"""

from html import escape
from html.parser import HTMLParser
from urllib.parse import urlsplit


# Etiquetas que se conservan tal cual en el mensaje.
_TAGS_PERMITIDOS = {
    'p', 'br', 'strong', 'b', 'em', 'i', 'u', 's', 'del',
    'ul', 'ol', 'li', 'blockquote', 'a', 'code', 'pre', 'hr',
    'h1', 'h2', 'h3', 'h4',
}

# Etiquetas cuyo contenido se descarta por completo.
_TAGS_DESCARTADOS = {
    'script', 'style', 'iframe', 'object', 'embed', 'svg', 'math',
}

# Etiquetas transparentes: se elimina la etiqueta pero se conserva el texto.
_TAGS_TRANSPARENTES = {'span', 'font'}

_TAGS_SIN_CIERRE = {'br', 'hr'}

_HREF_ESQUEMAS_PERMITIDOS = {'http', 'https', 'mailto', 'tel'}

_BLOQUES_TEXTO = {
    'p', 'div', 'li', 'h1', 'h2', 'h3', 'h4',
    'blockquote', 'pre', 'tr',
}

# Caracteres invisibles que no cuentan como contenido real.
_INVISIBLES = dict.fromkeys(
    ord(c) for c in '\u200b\u200c\u200d\u2060\ufeff\u00ad')


def _href_seguro(valor):
    """Devuelve el href si es seguro para mostrarlo; si no, None."""
    if not valor:
        return None
    valor = valor.strip()
    if not valor:
        return None
    partes = urlsplit(valor)
    esquema = (partes.scheme or '').lower()
    if esquema:
        return valor if esquema in _HREF_ESQUEMAS_PERMITIDOS else None
    # Evita URLs protocol-relative (//sitio o \\sitio) y esquemas camuflados.
    if (len(valor) >= 2 and valor[0] in ('/', '\\')
            and valor[1] in ('/', '\\')):
        return None
    if ':' in valor.split('/', 1)[0].split('?', 1)[0]:
        return None
    return valor


class _LimpiadorHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._salida = []
        self._pila = []
        self._en_pila = set()
        self._saltar = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in _TAGS_DESCARTADOS:
            self._saltar += 1
            return
        if self._saltar:
            return
        if tag in _TAGS_TRANSPARENTES:
            return
        if tag == 'div':
            tag = 'p'
        if tag not in _TAGS_PERMITIDOS:
            return

        atributos = ''
        if tag == 'a':
            href = next((v for k, v in attrs if k.lower() == 'href'), None)
            seguro = _href_seguro(href)
            if seguro is not None:
                atributos = (f' href="{escape(seguro, quote=True)}"'
                             ' rel="noopener noreferrer"')
        self._salida.append(f'<{tag}{atributos}>')
        if tag not in _TAGS_SIN_CIERRE:
            self._pila.append(tag)
            self._en_pila.add(tag)

    def handle_startendtag(self, tag, attrs):
        # Una etiqueta descartada autocerrada no abre un bloque que haya que
        # saltar: si se incrementara el contador, se perdería el texto siguiente.
        if tag.lower() in _TAGS_DESCARTADOS:
            return
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in _TAGS_DESCARTADOS:
            if self._saltar:
                self._saltar -= 1
            return
        if self._saltar:
            return
        if tag == 'div':
            tag = 'p'
        if (tag in _TAGS_TRANSPARENTES or tag not in _TAGS_PERMITIDOS
                or tag in _TAGS_SIN_CIERRE):
            return
        if tag in self._en_pila:
            while self._pila:
                actual = self._pila.pop()
                self._en_pila.discard(actual)
                self._salida.append(f'</{actual}>')
                if actual == tag:
                    break

    def handle_data(self, data):
        if not self._saltar:
            self._salida.append(escape(data))

    def resultado(self):
        while self._pila:
            actual = self._pila.pop()
            self._en_pila.discard(actual)
            self._salida.append(f'</{actual}>')
        return ''.join(self._salida)


def sanitizar_html(texto):
    """Devuelve el HTML del mensaje limitado a etiquetas y atributos seguros."""
    if not texto:
        return ''
    parser = _LimpiadorHTML()
    parser.feed(texto)
    parser.close()
    return parser.resultado()


class _ExtractorTexto(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._partes = []
        self._saltar = 0

    def _salto(self):
        if self._partes and not self._partes[-1].endswith('\n'):
            self._partes.append('\n')

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in _TAGS_DESCARTADOS:
            self._saltar += 1
            return
        if self._saltar:
            return
        if tag == 'br':
            self._partes.append('\n')
        elif tag in _BLOQUES_TEXTO:
            self._salto()
            if tag == 'li':
                self._partes.append('- ')

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in _TAGS_DESCARTADOS:
            if self._saltar:
                self._saltar -= 1
            return
        if self._saltar:
            return
        if tag in _BLOQUES_TEXTO:
            self._salto()

    def handle_data(self, data):
        if not self._saltar:
            self._partes.append(data)

    def texto(self):
        crudo = ''.join(self._partes).translate(_INVISIBLES)
        lineas = [linea.strip() for linea in crudo.splitlines()]
        resultado = []
        for linea in lineas:
            if not linea and (not resultado or not resultado[-1]):
                continue
            resultado.append(linea)
        return '\n'.join(resultado).strip()


def html_a_texto(texto_html):
    """Convierte el HTML del mensaje en texto plano legible."""
    if not texto_html:
        return ''
    parser = _ExtractorTexto()
    parser.feed(texto_html)
    parser.close()
    return parser.texto()
