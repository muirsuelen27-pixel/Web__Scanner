"""Configuración y validación de argumentos de Web Scanner."""

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class ScannerConfig:
    target: str = 'http://localhost'
    workers: int = 20
    timeout: float = 10.0
    port_timeout: float = 2.0
    rate_limit: float = 0.0
    max_redirects: int = 5

    def __post_init__(self) -> None:
        parsed = urlparse(self.target)
        if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
            raise ValueError('El objetivo debe ser una URL http o https válida')
        if not 1 <= self.workers <= 100:
            raise ValueError('workers debe estar entre 1 y 100')
        if self.timeout <= 0 or self.port_timeout <= 0:
            raise ValueError('Los timeouts deben ser mayores que cero')
        if self.rate_limit < 0:
            raise ValueError('rate_limit no puede ser negativo')
        if not 0 <= self.max_redirects <= 20:
            raise ValueError('max_redirects debe estar entre 0 y 20')


def normalize_target(target: str) -> str:
    value = target.strip()
    if '://' not in value:
        value = f'https://{value}'
    parsed = urlparse(value)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
        raise ValueError('El objetivo debe ser una URL http o https válida')
    return value
