"""Motor de análisis defensivo: datos primero, presentación después."""

from __future__ import annotations

import socket
import ssl
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urlparse

from .config import ScannerConfig
from .models import Finding, ScanResult
from .modules.headers import MODERN_SECURITY_HEADERS, evaluate_headers
from .modules.http import cloudflare_edge_ips, detect_cloudflare
from .modules.Tecnologias import detect_technologies
from .network import HttpClient, NetworkError

ProgressCallback = Callable[[str, int, int], None]
logger = logging.getLogger(__name__)


class DefensiveScanner:
    """Ejecuta sólo comprobaciones de bajo impacto y basadas en evidencia."""

    def __init__(self, config: ScannerConfig, progress: ProgressCallback | None = None) -> None:
        self.config = config
        self.progress = progress or (lambda _label, _step, _total: None)
        self.result = ScanResult(
            target=config.target,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

    def run(self, modules: tuple[str, ...] = ('dns', 'http', 'headers', 'tls')) -> ScanResult:
        operations = {
            'dns': self._inspect_dns,
            'http': self._inspect_http,
            'headers': self._inspect_headers,
            'tls': self._inspect_tls,
        }
        requested = tuple(name for name in modules if name in operations)
        selected_list: list[str] = []
        for name in requested:
            # Headers siempre se evalúan contra una respuesta HTTP observada. La
            # dependencia se ejecuta automáticamente y queda registrada.
            if name == 'headers' and 'http' not in selected_list:
                selected_list.append('http')
            if name not in selected_list:
                selected_list.append(name)
        selected = tuple(selected_list)
        self.result.metadata['modules'] = {
            'requested': list(requested),
            'executed': list(selected),
        }
        total = len(selected)
        for index, name in enumerate(selected, start=1):
            self.progress(self._label(name), index - 1, total)
            try:
                operations[name]()
            except Exception as error:  # isolation boundary: a module must not stop the report
                logger.debug(
                    'Módulo %s no concluyente durante el análisis de %s',
                    name, self.config.target, exc_info=True,
                )
                self.result.errors.append(f'{name}: {type(error).__name__}')
                self.result.add(Finding(
                    'INFO', f'Módulo no concluyente: {name.upper()}',
                    'La comprobación no pudo completarse, sin implicar un problema remoto.',
                    type(error).__name__, 'No se ha establecido impacto.',
                    'Revise conectividad, DNS y timeout antes de volver a intentarlo.', 'HIGH', 'Not conclusive',
                ))
            self.progress(self._label(name), index, total)
        self.result.completed_at = datetime.now(timezone.utc).isoformat()
        return self.result

    def _inspect_dns(self) -> None:
        host = urlparse(self.config.target).hostname
        if not host:
            return
        try:
            addresses = sorted({entry[4][0] for entry in socket.getaddrinfo(host, None)})
        except socket.gaierror as error:
            self.result.errors.append('dns: resolution failed')
            self.result.add(Finding(
                'INFO', 'DNS no concluyente', 'No fue posible resolver el dominio.',
                type(error).__name__, 'No se ha establecido impacto.',
                'Verifique el nombre de dominio y la conectividad DNS local.', 'HIGH', 'Not conclusive',
            ))
            return
        self.result.metadata['dns'] = {'host': host, 'addresses': addresses}
        self.result.add(Finding(
            'INFO', 'Resolución DNS completada', 'El objetivo resolvió direcciones IP públicas.',
            ', '.join(addresses[:8]) or 'Sin direcciones', 'Informativo.',
            'Use esta información sólo para identificar el objetivo autorizado.', 'HIGH', 'Observed',
        ))

    def _inspect_http(self) -> None:
        client = HttpClient(self.config)
        try:
            response = client.get(self.config.target, capture_text=True)
        finally:
            close = getattr(client, 'close', None)
            if callable(close):
                close()
        self.result.metadata['http'] = {
            'status': response.status,
            'final_url': response.url,
            'elapsed_ms': response.elapsed_ms,
            'content_length': response.content_length,
            'headers': self._safe_headers(response.headers),
        }
        content_type = response.headers.get('Content-Type', '').lower()
        html = response.text if 'text/html' in content_type or 'application/xhtml+xml' in content_type else ''
        self.result.metadata['technologies'] = [
            asdict(technology)
            for technology in detect_technologies(response.headers, html)
        ]
        self.result.add(Finding(
            'INFO', 'Respuesta HTTP observada', 'Se recibió una respuesta HTTP del objetivo.',
            f'HTTP {response.status} en {response.elapsed_ms} ms', 'Informativo.',
            'Revise el detalle de headers y los módulos de configuración.', 'HIGH', 'Observed',
        ))
        dns_metadata = self.result.metadata.get('dns', {})
        addresses = dns_metadata.get('addresses', []) if isinstance(dns_metadata, dict) else []
        edge_addresses = cloudflare_edge_ips(addresses) if isinstance(addresses, list) else []
        proxy = detect_cloudflare(response.headers, edge_addresses)
        self.result.metadata['cloudflare'] = {'status': proxy.status, 'evidence': list(proxy.evidence)}
        if proxy.detected:
            self.result.add(Finding(
                'INFO', 'CDN o proxy Cloudflare detectado',
                'La evidencia indica un proxy/CDN; no identifica una IP de origen.',
                '; '.join(proxy.evidence), 'No se ha establecido impacto.',
                'Interprete las direcciones observadas como infraestructura de borde.', 'HIGH', 'Observed',
            ))
        server = response.headers.get('Server') or response.headers.get('server')
        if server:
            self.result.add(Finding(
                'INFO', 'Identificador de servidor observado',
                'La respuesta HTTP incluye un header Server; esto es información de plataforma, no una vulnerabilidad.',
                server[:160], 'Informativo.',
                'Evalúe si la política de publicación requiere reducir detalles de versión o plataforma.', 'HIGH', 'Observed',
            ))

    def _inspect_headers(self) -> None:
        http = self.result.metadata.get('http')
        if not isinstance(http, dict):
            raise NetworkError('El módulo HTTP debe ejecutarse antes de revisar headers.')
        headers = http.get('headers', {})
        present, missing = evaluate_headers(headers if isinstance(headers, dict) else {})
        self.result.metadata['security_headers'] = {'present': present, 'missing': missing}
        for header in missing:
            self.result.add(Finding(
                'LOW', f'Header ausente: {header}', MODERN_SECURITY_HEADERS[header],
                'Header no presente en la respuesta observada.',
                'La defensa en profundidad puede estar reducida.',
                f'Evalúe configurar {header} según los requisitos de la aplicación.', 'HIGH', 'Missing',
            ))

    def _inspect_tls(self) -> None:
        parsed = urlparse(self.config.target)
        if parsed.scheme != 'https' or not parsed.hostname:
            self.result.add(Finding(
                'INFO', 'TLS no aplicable', 'El objetivo no utiliza una URL HTTPS.',
                parsed.scheme or 'sin esquema', 'No se ha establecido impacto.',
                'Utilice HTTPS para proteger el tráfico de la aplicación.', 'HIGH', 'Not applicable',
            ))
            return
        port = parsed.port or 443
        context = ssl.create_default_context()
        try:
            with socket.create_connection((parsed.hostname, port), timeout=self.config.timeout) as raw:
                with context.wrap_socket(raw, server_hostname=parsed.hostname) as secure:
                    cipher = secure.cipher()
                    certificate = secure.getpeercert()
                    expires_at = certificate.get('notAfter') if certificate else None
                    self.result.metadata['tls'] = {
                        'version': secure.version(),
                        'cipher': cipher[0] if cipher else 'Unknown',
                        'expires_at': expires_at or 'Unknown',
                    }
        except socket.timeout as error:
            raise NetworkError('La comprobación TLS excedió el timeout.') from error
        except ssl.SSLError as error:
            raise NetworkError('La comprobación TLS no fue concluyente.') from error
        self.result.add(Finding(
            'INFO', 'TLS negociado', 'La biblioteca local validó la conexión TLS observada.',
            f"{self.result.metadata['tls']['version']} · {self.result.metadata['tls']['cipher']}",
            'Informativo.', 'Mantenga protocolos y cifrados modernos.', 'HIGH', 'Observed',
        ))
        expires_at = self.result.metadata['tls']['expires_at']
        if expires_at != 'Unknown':
            remaining_days = round((ssl.cert_time_to_seconds(expires_at) - datetime.now(timezone.utc).timestamp()) / 86400)
            self.result.metadata['tls']['days_until_expiry'] = remaining_days
            severity = 'MEDIUM' if remaining_days <= 30 else 'INFO'
            status = 'Review soon' if remaining_days <= 30 else 'Observed'
            self.result.add(Finding(
                severity, 'Vigencia del certificado TLS',
                'La fecha se obtuvo del certificado presentado durante la conexión.',
                f'{expires_at} ({remaining_days} día(s) restantes)',
                'La renovación tardía puede afectar la disponibilidad de HTTPS.' if remaining_days <= 30 else 'Informativo.',
                'Planifique la renovación y valide el despliegue del certificado.' if remaining_days <= 30 else 'Mantenga un proceso de renovación automatizado.',
                'HIGH', status,
            ))

    @staticmethod
    def _safe_headers(headers: dict[str, str]) -> dict[str, str]:
        sensitive = {'set-cookie', 'authorization', 'cookie'}
        return {
            name: '[REDACTED]' if name.lower() in sensitive else value[:300]
            for name, value in headers.items()
        }

    @staticmethod
    def _label(name: str) -> str:
        return {
            'dns': 'Resolviendo DNS',
            'http': 'Observando conexión HTTP',
            'headers': 'Evaluando headers de seguridad',
            'tls': 'Validando TLS',
        }[name]
