"""Evaluación pura de headers de seguridad modernos."""

MODERN_SECURITY_HEADERS = {
    'Strict-Transport-Security': 'Protección contra downgrade de HTTPS',
    'Content-Security-Policy': 'Reduce XSS y contenido no autorizado',
    'X-Content-Type-Options': 'Evita MIME sniffing',
    'X-Frame-Options': 'Reduce clickjacking en navegadores antiguos',
    'Referrer-Policy': 'Limita información enviada en Referer',
    'Permissions-Policy': 'Restringe APIs del navegador',
}


def evaluate_headers(headers: dict[str, str] | None) -> tuple[list[str], list[str]]:
    normalized = {key.lower(): value for key, value in (headers or {}).items()}
    present = [name for name in MODERN_SECURITY_HEADERS if name.lower() in normalized]
    missing = [name for name in MODERN_SECURITY_HEADERS if name not in present]
    return present, missing
