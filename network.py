"""Cliente HTTP seguro, predecible y reutilizable para módulos defensivos."""

from __future__ import annotations

import time
from dataclasses import dataclass

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import ScannerConfig


class NetworkError(RuntimeError):
    """Error de red sin filtrar datos de la respuesta."""


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    url: str
    elapsed_ms: int
    content_length: int
    text: str = ''
    truncated: bool = False


class HttpClient:
    """Sesión HTTP con reintentos, redirecciones y rate limit opcional."""

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self._last_request_at = 0.0
        self.session = requests.Session()
        # ``requests`` permite hasta 30 redirecciones por defecto. Ajustarlo en
        # la sesión evita recorrer una cadena larga antes de poder informarla.
        self.session.max_redirects = config.max_redirects
        retry = Retry(
            total=2, connect=2, read=2, backoff_factor=0.35,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(('GET', 'HEAD')), raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=4, pool_maxsize=4)
        self.session.mount('https://', adapter)
        self.session.mount('http://', adapter)
        self.session.headers.update({
            'User-Agent': 'WebScanner/4.0 (defensive authorized assessment)',
            'Accept': 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8',
        })

    def get(self, url: str, capture_text: bool = False) -> HttpResponse:
        self._respect_rate_limit()
        try:
            response = self.session.get(
                url, timeout=self.config.timeout, allow_redirects=True, stream=True,
            )
        except requests.exceptions.TooManyRedirects as error:
            raise NetworkError('El objetivo excedió el límite de redirecciones configurado.') from error
        except requests.exceptions.Timeout as error:
            raise NetworkError('La solicitud excedió el tiempo de espera.') from error
        except requests.exceptions.SSLError as error:
            raise NetworkError('No se pudo validar la conexión TLS.') from error
        except requests.exceptions.ConnectionError as error:
            raise NetworkError('No se pudo establecer una conexión con el objetivo.') from error
        except requests.RequestException as error:
            raise NetworkError('La solicitud HTTP no pudo completarse.') from error
        try:
            headers = {str(key): str(value) for key, value in response.headers.items()}
            raw_length = headers.get('Content-Length', '')
            content_length = int(raw_length) if raw_length.isdigit() else 0
            text = ''
            truncated = False
            content_type = headers.get('Content-Type', '').lower()
            capture_text = capture_text and (
                'text/html' in content_type or 'application/xhtml+xml' in content_type
            )
            if capture_text:
                max_bytes = 2 * 1024 * 1024
                captured = bytearray()
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    remaining = max_bytes + 1 - len(captured)
                    captured.extend(chunk[:remaining])
                    if len(captured) > max_bytes:
                        del captured[max_bytes:]
                        truncated = True
                        break
                text = bytes(captured).decode(response.encoding or 'utf-8', errors='replace')
            return HttpResponse(
                status=response.status_code,
                headers=headers,
                url=response.url,
                elapsed_ms=round(response.elapsed.total_seconds() * 1000),
                content_length=content_length,
                text=text,
                truncated=truncated,
            )
        finally:
            response.close()

    def close(self) -> None:
        self.session.close()

    def _respect_rate_limit(self) -> None:
        if not self.config.rate_limit:
            return
        remaining = self.config.rate_limit - (time.monotonic() - self._last_request_at)
        if remaining > 0:
            time.sleep(remaining)
        self._last_request_at = time.monotonic()
