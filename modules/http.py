"""Utilidades HTTP sin salida directa a consola."""

from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Mapping


CLOUDFLARE_NETWORKS = tuple(map(ip_network, (
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
    '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
    '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
    '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
)))


@dataclass(frozen=True)
class ProxyDetection:
    detected: bool
    evidence: tuple[str, ...]
    status: str


def detect_cloudflare(headers: Mapping[str, str] | None, cloudflare_ips: list[str] | None = None) -> ProxyDetection:
    headers = headers or {}
    evidence: list[str] = []
    signature_headers = {'cf-ray', 'cf-cache-status', 'cf-connecting-ip', 'cf-request-id'}
    for name, value in headers.items():
        normalized_name = name.lower()
        normalized_value = str(value).lower()
        if normalized_name in signature_headers or (
            normalized_name == 'server' and 'cloudflare' in normalized_value
        ):
            evidence.append(f'HTTP header: {name}')
    for address in cloudflare_ips or []:
        evidence.append(f'Cloudflare IP range: {address}')
    if evidence:
        return ProxyDetection(True, tuple(dict.fromkeys(evidence)), 'Detected')
    if not headers and not cloudflare_ips:
        return ProxyDetection(False, (), 'Not conclusive')
    return ProxyDetection(False, (), 'Not detected')


def cloudflare_edge_ips(addresses: list[str] | tuple[str, ...]) -> list[str]:
    """Devuelve sólo IPs DNS que pertenecen a rangos públicos de Cloudflare."""
    matches: list[str] = []
    for address in addresses:
        try:
            if any(ip_address(address) in network for network in CLOUDFLARE_NETWORKS):
                matches.append(address)
        except ValueError:
            continue
    return matches


def safe_content_metadata(status: int, headers: Mapping[str, str] | None) -> dict[str, str | int]:
    headers = headers or {}
    return {
        'status': status,
        'content_type': headers.get('Content-Type', 'unknown'),
        'size': headers.get('Content-Length', 'unknown'),
        'redirect': headers.get('Location', ''),
    }
