import requests

URL = 'https://example.com'  # Sustituye por una URL propia o autorizada.

PAYLOADS = ("'", '"', "' OR '1'='1", '" OR "1"="1')
SQL_ERROR_MARKERS = (
    'sql',
    'syntax error',
    'mysql',
    'sqlite',
    'postgresql',
    'ora-',
    'odbc',
    'database error',
)

def detect_sql_injection(url: str) -> bool:
    """Busca indicios de errores SQL en respuestas de una URL autorizada.

    Devuelve True si una respuesta contiene un marcador; esto es solo un
    indicio y no confirma por sí solo que exista una vulnerabilidad.
    """
    for payload in PAYLOADS:
        test_url = f"{url}{payload}"
        try:
            response = requests.get(test_url, timeout=5)
            response_text = response.text.lower()
            if any(marker in response_text for marker in SQL_ERROR_MARKERS):
                return True
        except requests.RequestException:
            # Continúa con el siguiente intento si este produjo un error HTTP/red.
            continue
    return False

def diccionario_sql_injection() -> dict[str, str]:
    """Devuelve definiciones breves de conceptos relacionados con SQLi."""
    return {
        'Inyección SQL': (
            'Vulnerabilidad que permite alterar las consultas que una aplicación '
            'envía a su base de datos.'
        ),
        'Cargas de prueba': (
            'Entradas controladas que se usan para comprobar cómo responde '
            'una aplicación.'
        ),
        'Inyección SQL ciega': (
            'Técnica en la que se infiere el comportamiento de la base de datos '
            'a partir de las respuestas de la aplicación.'
        ),
        'Inyección SQL basada en errores': (
            'Técnica que identifica indicios a partir de mensajes de error '
            'de la base de datos.'
        ),
        'Inyección SQL basada en UNION': (
            'Técnica que aprovecha consultas UNION para combinar resultados '
            'de consultas.'
        ),
    }


def main() -> None:
    """Ejecuta la comprobación y muestra el resultado en español."""
    if detect_sql_injection(URL):
        print(f'Se encontraron indicios de inyección SQL en {URL}.')
    else:
        print(f'No se encontraron indicios de inyección SQL en {URL}.')


if __name__ == '__main__':
    main()