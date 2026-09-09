#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                                                                                           
    Web Security Scanner & Analyzer Tool - Advanced Edition
    Author: FlkY
    Version: 3.0 (Enterprise Edition)
"""

import socket
import ssl
import sys
import argparse
import os
import re
import textwrap
import json
import time
import threading
import platform
import subprocess
import urllib.request
import urllib.parse
import urllib.error
import http.client
from datetime import datetime
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import base64
import random
import string
import ipaddress
import logging
from dataclasses import asdict, dataclass
from collections import defaultdict
from typing import Any, Dict, List, Optional

DEFAULT_WORDLIST_URL = (
    'https://raw.githubusercontent.com/danielmiessler/SecLists/master/'
    'Discovery/DNS/subdomains-top1million-5000.txt'
)
DEFAULT_WORDLIST_PATHS = (
    '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
    '/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt',
    '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
    '/usr/share/dnsrecon/namelist.txt',
)

COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS',
    587: 'SMTP Submission', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch',
    27017: 'MongoDB'
}

logger = logging.getLogger('web_scanner')


@dataclass
class Finding:
    severity: str
    title: str
    description: str
    evidence: str
    impact: str
    recommendation: str
    confidence: str
    status: str = 'Observed'


def redact(value: Any, limit: int = 80) -> str:
    """Redacta valores sensibles antes de mostrarlos o exportarlos."""
    text = str(value)
    if len(text) > limit:
        text = text[:limit] + '...'
    return text

# Manejo de imports opcionales
try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.rdatatype
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

# Configuración de colores ANSI
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    HIDDEN = '\033[8m'
    
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'
    
    # Colores brillantes
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

# Funciones de animación
class Animations:
    @staticmethod
    def wrap_text(text, width=78, subsequent_indent="  "):
        return textwrap.wrap(
            str(text),
            width=width,
            break_long_words=False,
            break_on_hyphens=False,
            subsequent_indent=subsequent_indent
        ) or [""]

    @staticmethod
    def loading_animation(duration=2, message="Cargando"):
        chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        end_time = time.time() + duration
        i = 0
        while time.time() < end_time:
            sys.stdout.write(f'\r{Colors.CYAN}{chars[i % len(chars)]} {message}...{Colors.RESET}')
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
        sys.stdout.write('\r' + ' ' * 50 + '\r')
        sys.stdout.flush()
    
    @staticmethod
    def progress_bar(progress, total, prefix="", suffix="", length=50):
        filled = int(length * progress // total)
        bar = '█' * filled + '░' * (length - filled)
        percent = f"{100 * (progress / float(total)):.1f}"
        print(f'\r{prefix} |{Colors.CYAN}{bar}{Colors.RESET}| {percent}% {suffix}', end='\r')
        if progress == total:
            print()

    @staticmethod
    def print_banner():
        banner = f"""
{Colors.BRIGHT_CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║  {Colors.BRIGHT_WHITE}╦ ╦┌─┐┌┐ ┌─┐┌─┐┌─┐┌─┐┌─┐┌┐┌┌┐┌┌─┐┬─┐{Colors.BRIGHT_CYAN}                                     ║
║  {Colors.BRIGHT_WHITE}║║║├┤ ├┴┐└─┐│  ├─┤└─┐├─┤││││││├┤ ├┬┘{Colors.BRIGHT_CYAN}                                     ║
║  {Colors.BRIGHT_WHITE}╚╩╝└─┘└─┘└─┘└─┘┴ ┴└─┘┴ ┴┘└┘┘└┘└─┘┴└─{Colors.BRIGHT_CYAN}                                     ║
║                                                                                  ║
║  {Colors.BRIGHT_GREEN}Advanced Security Scanner & Analyzer Tool v3.0{Colors.BRIGHT_CYAN}                              ║
║  {Colors.BRIGHT_YELLOW}Desarrollado por: FlkY {Colors.BRIGHT_CYAN}                       ║
║  {Colors.BRIGHT_BLUE}Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.BRIGHT_CYAN}                                ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
        """
        print(banner)

    @staticmethod
    def print_separator(color=Colors.CYAN):
        print(f"{color}{'='*100}{Colors.RESET}")

    @staticmethod
    def print_section(title):
        print(f"\n{Colors.BRIGHT_YELLOW}┌─ {Colors.BRIGHT_WHITE}{title} {Colors.BRIGHT_YELLOW}{'─'*50}┐{Colors.RESET}")
    
    @staticmethod
    def print_end_section():
        print(f"{Colors.BRIGHT_YELLOW}└{'─'*85}┘{Colors.RESET}\n")

class PortScanner:
    """Escaneo TCP connect opcional para una auditoría autorizada."""

    def __init__(self, target, timeout=2, max_workers=20):
        self.target = target
        self.timeout = timeout
        self.max_workers = max_workers
        self.open_ports = []

    def scan_port(self, port):
        try:
            with socket.create_connection((self.target, port), timeout=self.timeout):
                return port, True
        except (OSError, socket.timeout):
            return port, False

    def scan(self, ports=None):
        ports = ports or COMMON_PORTS
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            results = executor.map(self.scan_port, ports)
            self.open_ports = sorted(port for port, is_open in results if is_open)
        return self.open_ports


class WebScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.domain = self.parsed_url.hostname or self.parsed_url.netloc
        self.ip_addresses = []
        self.using_cloudflare = False
        self.real_ip = None
        self.technologies = []
        self.headers = {}
        self.cookies = {}
        self.security_headers = {}
        self.forms = []
        self.links = []
        self.subdomains = []
        self.open_ports = []
        self.vulnerabilities = []
        self.findings: List[Finding] = []
        self.session = None
        self.certificate_name = None
        self.brute_force_enabled = False
        self.wordlist_source = 'built-in'
        self.max_workers = 20
        self.request_timeout = 10
        self.port_scanner = None
        self.scan_ports_enabled = False
        self.port_timeout = 2
        self._runtime_initialized = False
        self.add_finding(
            'INFO', 'Runtime initialized', '', '', '', '', 'HIGH'
        )
        self.findings.clear()
        self.waf_status = 'Not conclusive'
        self.cloudflare_evidence = []

    def add_finding(self, severity: str, title: str, description: str,
                    evidence: str, impact: str, recommendation: str,
                    confidence: str, status: str = 'Observed') -> None:
        """Registra un hallazgo sin convertir una señal en vulnerabilidad."""
        self.findings.append(Finding(
            severity=severity.upper(),
            title=title,
            description=description,
            evidence=redact(evidence),
            impact=impact,
            recommendation=recommendation,
            confidence=confidence.upper(),
            status=status
        ))

        if self._runtime_initialized:
            return
        self._runtime_initialized = True
        
       # Wordlist extensa para fuerza bruta
        self.subdomain_wordlist = [
            # Subdominios comunes
            'www', 'mail', 'mx', 'mx1', 'mx2', 'smtp', 'webmail', 'ftp',
            'sftp', 'direct', 'origin', 'backend', 'server', 'host',
            'ns1', 'ns2', 'ns3', 'ns4', 'dns1', 'dns2', 'cpanel', 'whm',
            'webdisk', 'autodiscover', 'autoconfig', 'remote', 'vpn',
            'portal', 'admin', 'administrator', 'manage', 'management',
            'panel', 'control', 'secure', 'security', 'test', 'dev',
            'development', 'staging', 'stage', 'prod', 'production',
            'beta', 'alpha', 'demo', 'sandbox', 'api', 'apis', 'app',
            'apps', 'mobile', 'm', 'shop', 'store', 'billing', 'pay',
            'payment', 'checkout', 'cart', 'account', 'accounts', 'login',
            'auth', 'sso', 'cdn', 'static', 'assets', 'media', 'files',
            'download', 'downloads', 'upload', 'uploads', 'img', 'images',
            'video', 'videos', 'blog', 'news', 'forum', 'forums', 'wiki',
            'docs', 'documentation', 'help', 'support', 'status', 'monitor',
            'metrics', 'grafana', 'kibana', 'elastic', 'log', 'logs',
            'db', 'database', 'mysql', 'postgres', 'redis', 'mongo',
            'git', 'github', 'gitlab', 'bitbucket', 'jenkins', 'ci',
            'cd', 'docker', 'k8s', 'kubernetes', 'cloud', 'aws', 'azure',
            'gcp', 'firewall', 'proxy', 'loadbalancer', 'lb', 'cache',
            'varnish', 'haproxy', 'nginx', 'apache', 'iis', 'tomcat',
            'node', 'nodejs', 'python', 'php', 'ruby', 'java', 'go',
            'old', 'new', 'backup', 'backups', 'archive', 'archives',
            'internal', 'intranet', 'private', 'public', 'external',
            'web', 'web1', 'web2', 'web3', 'web4', 'web5', 'web6',
            'server1', 'server2', 'server3', 'server4', 'server5',
            'db1', 'db2', 'mail1', 'mail2', 'mail3', 'ns', 'dns',
            'vps', 'dedicated', 'shared', 'cluster', 'node1', 'node2',
            'host1', 'host2', 'host3', 'host4', 'host5', 'host6',
            'smtp1', 'smtp2', 'pop', 'pop3', 'imap', 'imap4',
            'ftp1', 'ftp2', 'sftp1', 'sftp2', 'ssh', 'telnet',
            'rdp', 'remote1', 'remote2', 'vpn1', 'vpn2', 'proxy1',
            'proxy2', 'firewall1', 'firewall2', 'router', 'gateway',
            'switch', 'access', 'wireless', 'wifi', 'mobile1', 'mobile2',
            'app1', 'app2', 'app3', 'api1', 'api2', 'api3', 'api4',
            'dev1', 'dev2', 'dev3', 'test1', 'test2', 'test3', 'test4',
            'staging1', 'staging2', 'staging3', 'prod1', 'prod2', 'prod3',
            'uat', 'qa', 'preprod', 'pre-prod', 'dr', 'disaster',
            'recovery', 'backup1', 'backup2', 'backup3', 'archive1',
            'archive2', 'archive3', 'storage', 'nas', 'san', 'file',
            'fileserver', 'print', 'printer', 'scan', 'scanner',
            'camera', 'cam', 'video1', 'video2', 'stream', 'streaming',
            'live', 'radio', 'tv', 'media1', 'media2', 'media3',
            'press', 'news1', 'news2', 'blog1', 'blog2', 'blog3',
            'forum1', 'forum2', 'forum3', 'community', 'social',
            'chat', 'messenger', 'email', 'mailer', 'newsletter',
            'campaign', 'marketing', 'ads', 'advert', 'advertising',
            'tracking', 'analytics', 'stats', 'statistics', 'metrics1',
            'metrics2', 'grafana1', 'grafana2', 'prometheus', 'alert',
            'alerts', 'notification', 'notifications', 'sms', 'push',
            'ws', 'websocket', 'socket', 'realtime', 'rt', 'stream1',
            'stream2', 'mqtt', 'iot', 'device', 'devices', 'sensor',
            'sensors', 'data', 'bigdata', 'hadoop', 'spark', 'ml',
            'ai', 'machine', 'learning', 'model', 'models', 'train',
            'training', 'inference', 'predict', 'prediction', 'api5',
            'api6', 'api7', 'api8', 'api9', 'api10', 'v1', 'v2',
            'v3', 'v4', 'v5', 'version', 'versions', 'release',
            'releases', 'download1', 'download2', 'download3', 'mirror',
            'mirror1', 'mirror2', 'mirror3', 'cdn1', 'cdn2', 'cdn3',
            'cdn4', 'cdn5', 'static1', 'static2', 'static3', 'static4',
            'assets1', 'assets2', 'assets3', 'assets4', 'img1', 'img2',
            'img3', 'img4', 'css', 'js', 'fonts', 'font', 'webfonts',
            'webfont', 'icon', 'icons', 'favicon', 'logo', 'logos',
            'banner', 'banners', 'ad', 'adserver', 'adtracker',
            'pixel', 'tracker', 'beacon', 'analytics1', 'analytics2',
            'analytics3', 'stats1', 'stats2', 'stats3', 'report',
            'reports', 'dashboard', 'dashboards', 'admin1', 'admin2',
            'admin3', 'admin4', 'admin5', 'root', 'superuser',
            'superadmin', 'sysadmin', 'system', 'systems', 'config',
            'configuration', 'settings', 'setup', 'install', 'update',
            'updates', 'upgrade', 'upgrades', 'patch', 'patches',
            'security1', 'security2', 'secure1', 'secure2', 'ssl',
            'tls', 'cert', 'certs', 'certificate', 'certificates',
            'key', 'keys', 'pki', 'ca', 'authority', 'sign', 'signing',
            
            # --- NUEVOS: Cloud, DevOps, Contenedores y Microservicios ---
            'ingress', 'istio', 'envoy', 'traefik', 'consul', 'vault',
            'nomad', 'argo', 'argocd', 'flux', 'helm', 'rancher',
            'portainer', 'minio', 's3', 'registry', 'harbor', 'artifact',
            'artifacts', 'nexus', 'artifactory', 'sonar', 'sonarqube',
            'jira', 'confluence', 'linear', 'mattermost', 'slack',
            'keycloak', 'okta', 'auth0', 'oauth', 'oauth2', 'saml',
            'ldap', 'ad', 'domaincontroller', 'radius', 'tacacs',
            
            # --- NUEVOS: Monitoreo, Logs y Telemetría avanzada ---
            'otel', 'opentelemetry', 'jaeger', 'zipkin', 'prometheus1',
            'zabbix', 'nagios', 'icinga', 'statuspage', 'ping', 'uptime',
            'sentry', 'fluentd', 'logstash', 'splunk', 'datadog',
            'newrelic', 'dynatrace', 'opensearch',
            
            # --- NUEVOS: Entornos de desarrollo específicos y emergentes ---
            'sandbox1', 'sandbox2', 'lab', 'labs', 'research', 'poc',
            'proof', 'temp', 'temporary', 'ghost', 'shadow', 'leak',
            'internal-api', 'private-api', 'graphql', 'grpc', 'rpc',
            'swagger', 'openapi', 'redoc', 'sandbox-api', 'dev-api',
            'staging-api', 'test-api', 'partner', 'partners', 'vendor',
            'vendors', 'client', 'clients', 'customer', 'customers',
            'b2b', 'b2c', 'enterprise', 'corp', 'corporate', 'hr',
            'payroll', 'jobs', 'careers', 'hire', 'hiring', 'talent',
            'investor', 'investors', 'legal', 'compliance', 'privacy',
            'terms', 'trust', 'status-api', 'mail-archive', 'smtp-relay'
        ]

        self.subdomain_wordlist = list(dict.fromkeys(self.subdomain_wordlist))

        if REQUESTS_AVAILABLE:
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            })

    # ==================== NUEVAS FUNCIONES ====================

    def check_xss(self):
        """Detecta vulnerabilidades XSS (reflejado)"""
        Animations.print_section("DETECCIÓN DE XSS")
        if not REQUESTS_AVAILABLE or not BS4_AVAILABLE:
            print(f"{Colors.YELLOW}!{Colors.RESET} Requiere requests y beautifulsoup4")
            Animations.print_end_section()
            return

        xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            "'><script>alert(1)</script>",
            '"><svg onload=alert(1)>',
            'javascript:alert(1)'
        ]
        found = False
        try:
            response = self.session.get(self.target_url, timeout=self.request_timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            print(f"{Colors.CYAN}→{Colors.RESET} {len(forms)} formularios encontrados")
            for form in forms:
                action = form.get('action', self.target_url)
                method = form.get('method', 'get').upper()
                inputs = form.find_all(['input', 'textarea'])
                for input_field in inputs:
                    name = input_field.get('name')
                    if not name:
                        continue
                    for payload in xss_payloads[:3]:
                        data = {inp.get('name'): 'test' for inp in inputs if inp.get('name')}
                        data[name] = payload
                        try:
                            if method == 'POST':
                                r = self.session.post(action, data=data, timeout=self.request_timeout)
                            else:
                                r = self.session.get(action, params=data, timeout=self.request_timeout)
                            if payload in r.text:
                                print(f"{Colors.BRIGHT_YELLOW}! XSS REFLEJADO POTENCIAL (NO CONFIRMADO){Colors.RESET}")
                                print(f"  Campo: {name}")
                                print(f"  Payload: [REDACTED TEST MARKER]")
                                self.add_finding(
                                    'MEDIUM', 'Reflected input observed',
                                    'A harmless test marker was reflected in the response.',
                                    f'Parameter {name} reflected a controlled marker',
                                    'Reflection may become client-side script execution depending on context and encoding.',
                                    'Review output encoding and context-specific input handling.',
                                    'Medium', status='Potential; not confirmed'
                                )
                                found = True
                                break
                        except:
                            pass
            # Test en parámetros GET
            parsed = urlparse(self.target_url)
            if parsed.query:
                params = urllib.parse.parse_qs(parsed.query)
                for param in params:
                    for payload in xss_payloads[:3]:
                        test_params = params.copy()
                        test_params[param] = payload
                        try:
                            r = self.session.get(self.target_url.split('?')[0], params=test_params, timeout=self.request_timeout)
                            if payload in r.text:
                                print(f"{Colors.BRIGHT_YELLOW}! XSS POTENCIAL EN PARÁMETRO GET (NO CONFIRMADO){Colors.RESET}")
                                print(f"  Parámetro: {param}")
                                print(f"  Payload: [REDACTED TEST MARKER]")
                                self.add_finding(
                                    'MEDIUM', 'Reflected GET parameter observed',
                                    'A controlled test marker was reflected by a GET parameter.',
                                    f'Parameter {param} reflected a controlled marker',
                                    'Reflection alone does not prove script execution.',
                                    'Review contextual output encoding for this parameter.',
                                    'Medium', status='Potential; not confirmed'
                                )
                                found = True
                                break
                        except:
                            pass
            if not found:
                print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} No se detectaron XSS reflejados")
        except Exception as e:
            print(f"{Colors.RED}✗{Colors.RESET} Error: {str(e)}")
        Animations.print_end_section()

    def detect_waf(self):
        """Detecta Web Application Firewall (WAF)"""
        Animations.print_section("DETECCIÓN DE WAF")
        waf_signatures = {
            'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare', 'cf-cache-status'],
            'Akamai': ['akamai', 'x-akamai-transformed', 'x-akamai-request-id'],
            'Imperva Incapsula': ['incapsula', 'x-iinfo', 'x-cdn'],
            'AWS WAF': ['awselb', 'x-amz-cf-id', 'x-amzn-requestid'],
            'Sucuri': ['sucuri', 'x-sucuri-id', 'x-sucuri-cache'],
            'F5 BIG-IP': ['f5', 'x-cnection', 'x-wa-info'],
            'ModSecurity': ['mod_security', 'modsecurity', 'x-mod-security'],
            'Barracuda': ['barracuda', 'x-barracuda'],
            'Citrix NetScaler': ['citrix', 'ns_af', 'x-ns'],
            'Fortinet FortiWeb': ['fortiweb', 'x-fortiweb'],
            'DenyAll': ['denyall', 'x-denyall'],
            'Wordfence': ['wordfence', 'x-wordfence'],
            'Comodo WAF': ['comodo', 'x-cwaf'],
            'Radware AppWall': ['radware', 'x-sl-zone'],
        }
        detected = []
        proxy_evidence = []
        # Revisar headers
        for header, value in self.headers.items():
            header_str = f"{header}: {value}".lower()
            if any(signature in header_str for signature in waf_signatures['Cloudflare']):
                proxy_evidence.append(f'{header}: {redact(value)}')
            for waf, sigs in waf_signatures.items():
                if waf == 'Cloudflare':
                    continue
                if any(sig in header_str for sig in sigs):
                    if waf not in detected:
                        detected.append(waf)
                        print(f"{Colors.BRIGHT_RED}⚠ WAF detectado: {waf}{Colors.RESET}")
                        print(f"  Header: {header}: {redact(value)}")
        # Revisar cookies
        for cookie in self.cookies:
            cookie_lower = cookie.lower()
            for waf, sigs in waf_signatures.items():
                if waf == 'Cloudflare':
                    continue
                if any(sig in cookie_lower for sig in sigs):
                    if waf not in detected:
                        detected.append(waf)
                        print(f"{Colors.BRIGHT_RED}⚠ WAF detectado en cookie: {waf}{Colors.RESET}")
        if detected:
            self.waf_status = 'Identified by response signature'
        elif proxy_evidence or self.using_cloudflare:
            self.waf_status = 'Not confirmed'
            print(f"{Colors.BRIGHT_YELLOW}ℹ{Colors.RESET} WAF: No confirmado")
            print(f"  Cloudflare/CDN proxy evidence exists, but WAF behavior was not independently verified.")
        else:
            self.waf_status = 'Not identified'
            print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} WAF no identificado")
        Animations.print_end_section()

    def check_ssl_tls(self):
        """Comprueba la versión negociada y protocolos remotos verificables."""
        Animations.print_section("ANÁLISIS SSL/TLS")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=self.request_timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as secure_sock:
                    version = secure_sock.version() or 'Unknown'
                    cipher = secure_sock.cipher()
                    print(f"{Colors.CYAN}→{Colors.RESET} Protocolo negociado: {version}")
                    print(f"{Colors.CYAN}→{Colors.RESET} Cipher: {cipher[0] if cipher else 'Unknown'}")
                    print(f"{Colors.CYAN}→{Colors.RESET} Certificado validado por la librería local")

            protocol_bounds = {
                'TLSv1.2': ssl.TLSVersion.TLSv1_2,
            }
            for legacy_protocol in ('TLSv1', 'TLSv1.1'):
                print(f"  {legacy_protocol}: Remote: Not tested | Local probe: unavailable")
            for protocol, version_value in protocol_bounds.items():
                try:
                    probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    probe.minimum_version = version_value
                    probe.maximum_version = version_value
                    probe.check_hostname = False
                    probe.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((self.domain, 443), timeout=5) as sock:
                        with probe.wrap_socket(sock, server_hostname=self.domain):
                            status = 'Supported by remote server'
                except ValueError:
                    status = 'Remote: Not tested | Local probe: unavailable'
                except ssl.SSLError:
                    status = 'Remote: Not tested | Local probe: rejected or unavailable'
                except OSError:
                    status = 'Remote: Not tested | Network probe failed'
                print(f"  {protocol}: {status}")
                if protocol in ('TLSv1', 'TLSv1.1') and status == 'Supported by remote server':
                    self.add_finding(
                        'MEDIUM', f'Legacy {protocol} supported',
                        'The remote endpoint negotiated a legacy TLS protocol.',
                        f'{protocol} handshake succeeded against {self.domain}:443',
                        'Legacy protocol support weakens transport security.',
                        'Disable legacy TLS protocols and require TLS 1.2 or newer.',
                        'High', status='Potentially insecure configuration'
                    )
        except (OSError, ssl.SSLError) as error:
            print(f"{Colors.YELLOW}!{Colors.RESET} TLS no concluyente: {error}")
        Animations.print_end_section()

    def discover_content(self):
        """Descubre directorios y archivos comunes"""
        Animations.print_section("DESCUBRIMIENTO DE CONTENIDO")
        common_paths = [
            '/admin', '/administrator', '/backup', '/backups', '/.git',
            '/.env', '/.htaccess', '/robots.txt', '/sitemap.xml',
            '/wp-admin', '/wp-content', '/wp-includes', '/phpinfo.php',
            '/server-status', '/config.php', '/.DS_Store', '/.svn',
            '/.hg', '/.bzr', '/.well-known', '/api', '/graphql',
            '/swagger', '/openapi.json', '/readme.md', '/CHANGELOG.txt',
            '/.bash_history', '/.ssh', '/id_rsa', '/id_dsa',
            '/dump.sql', '/database.sql', '/db.sql', '/.mysql_history'
        ]
        found = False
        for path in common_paths:
            url = urljoin(self.target_url, path)
            try:
                r = self.session.get(url, timeout=5, allow_redirects=False)
                if r.status_code in [200, 301, 302, 403]:
                    location = redact(r.headers.get('Location', ''))
                    content_type = r.headers.get('Content-Type', 'unknown')
                    size = r.headers.get('Content-Length', 'unknown')
                    print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} Endpoint discovered: {url}")
                    print(f"  Status: {r.status_code} | Content-Type: {content_type} | Size: {size}")
                    if location:
                        print(f"  Redirect: {location}")
                    found = True
            except:
                pass
        if not found:
            print(f"{Colors.YELLOW}!{Colors.RESET} No se encontraron rutas sensibles")
        Animations.print_end_section()

    def check_backup_files(self):
        """Busca archivos de backup expuestos"""
        Animations.print_section("ARCHIVOS DE BACKUP")
        backup_paths = [
            '/backup.zip', '/backup.tar.gz', '/backup.sql', '/site.zip',
            '/www.zip', '/html.zip', '/database.zip', '/db.zip',
            '/.env.bak', '/.env.old', '/config.php.bak', '/config.php~',
            '/wp-config.php.bak', '/.htaccess.bak', '/index.php.bak'
        ]
        found = False
        for path in backup_paths:
            url = urljoin(self.target_url, path)
            try:
                r = self.session.head(url, timeout=5, allow_redirects=False)
                if r.status_code == 200:
                    print(f"{Colors.BRIGHT_RED}⚠ Backup expuesto: {url}{Colors.RESET}")
                    found = True
            except:
                pass
        if not found:
            print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} No se encontraron backups expuestos")
        Animations.print_end_section()

    def check_git_exposure(self):
        """Detecta repositorio .git expuesto"""
        Animations.print_section("EXPOSICIÓN DE GIT")
        git_paths = ['/.git/config', '/.git/HEAD', '/.gitignore', '/.git/logs/HEAD']
        found = False
        for path in git_paths:
            url = urljoin(self.target_url, path)
            try:
                r = self.session.get(url, timeout=5, allow_redirects=False)
                if r.status_code == 200 and ('refs' in r.text or 'repository' in r.text.lower()):
                    print(f"{Colors.BRIGHT_RED}⚠ Repositorio Git expuesto: {url}{Colors.RESET}")
                    found = True
            except:
                pass
        if not found:
            print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} No se detectó .git expuesto")
        Animations.print_end_section()

    def discover_apis(self):
        """Busca endpoints de API comunes"""
        Animations.print_section("DESCUBRIMIENTO DE APIs")
        api_paths = [
            '/api/v1/', '/api/v2/', '/api/', '/graphql', '/swagger',
            '/swagger-ui.html', '/openapi.json', '/api/docs', '/rest/',
            '/wp-json/wp/v2/', '/api/users', '/api/login'
        ]
        found = False
        for path in api_paths:
            url = urljoin(self.target_url, path)
            try:
                r = self.session.get(url, timeout=5, allow_redirects=False)
                if r.status_code in [200, 401, 403] and ('json' in r.headers.get('content-type', '') or 'api' in r.url):
                    print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} {url} → {r.status_code}")
                    found = True
            except:
                pass
        if not found:
            print(f"{Colors.YELLOW}!{Colors.RESET} No se encontraron APIs obvias")
        Animations.print_end_section()

    def test_jwt(self):
        """Identifica estructuras JWT sin imprimir ni validar secretos."""
        Animations.print_section("ANÁLISIS JWT")
        jwt_candidates = []
        for name, value in self.cookies.items():
            if len(value.split('.')) == 3:
                jwt_candidates.append((name, value))
        for header, value in self.headers.items():
            if 'authorization' in header.lower() and 'bearer' in value.lower():
                token = value.split(' ', 1)[-1].strip()
                if len(token.split('.')) == 3:
                    jwt_candidates.append((header, token))
        if not jwt_candidates:
            print(f"{Colors.YELLOW}!{Colors.RESET} No se detectó estructura JWT")
            if any(re.search(r'(csrf|xsrf)', name, re.I) for name in self.cookies):
                print(f"{Colors.CYAN}→{Colors.RESET} CSRF token detected; no JWT structure detected")
        else:
            for name, token in jwt_candidates:
                print(f"{Colors.CYAN}→{Colors.RESET} Estructura JWT detectada en {name}: [REDACTED]")
                try:
                    parts = token.split('.')
                    payload = parts[1] + '=' * (-len(parts[1]) % 4)
                    decoded = json.loads(base64.urlsafe_b64decode(payload).decode('utf-8'))
                    safe_claims = {key: decoded[key] for key in ('alg', 'typ', 'exp', 'iss', 'aud') if key in decoded}
                    print(f"  Claims no sensibles: {safe_claims}")
                except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
                    print(f"  Payload JWT no concluyente")
        Animations.print_end_section()

    def check_default_credentials(self):
        """Prueba credenciales por defecto en formularios de login"""
        Animations.print_section("CREDENCIALES POR DEFECTO")
        if not REQUESTS_AVAILABLE or not BS4_AVAILABLE:
            return
        common_creds = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
            ('root', 'root'), ('root', 'toor'), ('test', 'test'),
            ('user', 'user'), ('guest', 'guest'), ('admin', 'admin123')
        ]
        try:
            response = self.session.get(self.target_url, timeout=self.request_timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                if 'login' in form.get('action', '').lower() or 'login' in str(form).lower():
                    action = form.get('action', self.target_url)
                    method = form.get('method', 'get').upper()
                    inputs = form.find_all('input')
                    user_field = None
                    pass_field = None
                    for inp in inputs:
                        if inp.get('type') == 'password':
                            pass_field = inp.get('name')
                        elif inp.get('type') == 'text':
                            user_field = inp.get('name')
                    if user_field and pass_field:
                        for user, pwd in common_creds:
                            data = {user_field: user, pass_field: pwd}
                            try:
                                if method == 'POST':
                                    r = self.session.post(action, data=data, timeout=5)
                                else:
                                    r = self.session.get(action, params=data, timeout=5)
                                # Criterio simple: redirección o cambio en cookies
                                if r.status_code == 302 or 'logout' in r.text.lower() or 'dashboard' in r.text.lower():
                                    print(f"{Colors.BRIGHT_RED}⚠ Credenciales por defecto exitosas: username={redact(user, 20)}, password=[REDACTED]{Colors.RESET}")
                                    break
                            except:
                                pass
        except:
            pass
        print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} Prueba de credenciales completada")
        Animations.print_end_section()

    # ==================== FIN NUEVAS FUNCIONES ====================

    def load_subdomain_wordlist(self, source=None):
        """Carga subdominios desde un archivo local o una URL pública."""
        if source is None:
            source = next(
                (path for path in DEFAULT_WORDLIST_PATHS if os.path.isfile(path)),
                DEFAULT_WORDLIST_URL
            )
        try:
            if source.startswith(('http://', 'https://')):
                with urllib.request.urlopen(source, timeout=15) as response:
                    content = response.read().decode('utf-8', errors='replace')
                self.wordlist_source = source
            else:
                with open(source, 'r', encoding='utf-8') as wordlist_file:
                    content = wordlist_file.read()
                self.wordlist_source = os.path.abspath(source)
        except (OSError, urllib.error.URLError) as error:
            print(f"{Colors.YELLOW}!{Colors.RESET} No se pudo cargar el wordlist externo: {error}")
            print(f"{Colors.YELLOW}!{Colors.RESET} Se usara el wordlist integrado ({len(self.subdomain_wordlist)} entradas)")
            return len(self.subdomain_wordlist)

        entries = set()
        for line in content.splitlines():
            entry = line.split('#', 1)[0].strip().lower().rstrip('.')
            if entry.startswith('*.'):
                entry = entry[2:]
            if not entry or '.' in entry or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', entry):
                continue
            entries.add(entry)

        if entries:
            self.subdomain_wordlist = sorted(entries)
        print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} Wordlist cargado: {len(self.subdomain_wordlist)} entradas")
        return len(self.subdomain_wordlist)
    
    def resolve_dns(self):
        """Resuelve la información DNS del dominio"""
        Animations.print_section("RESOLUCIÓN DNS")
        
        try:
            if DNS_AVAILABLE:
                # Registros A
                try:
                    answers = dns.resolver.resolve(self.domain, 'A')
                    print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} {Colors.BOLD}Registros A:{Colors.RESET}")
                    for rdata in answers:
                        ip = str(rdata)
                        self.ip_addresses.append(ip)
                        label = 'Observed Cloudflare edge IP' if self.is_cloudflare_ip(ip) else 'Observed IP'
                        print(f"  {Colors.CYAN}→{Colors.RESET} {label}: {ip}")
                except:
                    print(f"{Colors.RED}✗{Colors.RESET} No se pudieron obtener registros A")
                
                # Registros AAAA (IPv6)
                try:
                    answers = dns.resolver.resolve(self.domain, 'AAAA')
                    print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} {Colors.BOLD}Registros AAAA (IPv6):{Colors.RESET}")
                    for rdata in answers:
                        print(f"  {Colors.CYAN}→{Colors.RESET} {str(rdata)}")
                except:
                    print(f"{Colors.YELLOW}!{Colors.RESET} No hay registros AAAA")
                
                # Registros MX
                try:
                    answers = dns.resolver.resolve(self.domain, 'MX')
                    print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} {Colors.BOLD}Servidores de correo (MX):{Colors.RESET}")
                    for rdata in answers:
                        print(f"  {Colors.CYAN}→{Colors.RESET} {rdata.exchange} (prioridad: {rdata.preference})")
                except:
                    print(f"{Colors.YELLOW}!{Colors.RESET} No hay registros MX")
                
                # Registros NS
                try:
                    answers = dns.resolver.resolve(self.domain, 'NS')
                    print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} {Colors.BOLD}Servidores de nombres (NS):{Colors.RESET}")
                    for rdata in answers:
                        ns = str(rdata)
                        self.subdomains.append(ns)
                        print(f"  {Colors.CYAN}→{Colors.RESET} {ns}")
                except:
                    print(f"{Colors.YELLOW}!{Colors.RESET} No hay registros NS")
                
                # Registros TXT
                try:
                    answers = dns.resolver.resolve(self.domain, 'TXT')
                    print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} {Colors.BOLD}Registros TXT:{Colors.RESET}")
                    for rdata in answers:
                        txt = str(rdata)
                        if len(txt) > 100:
                            txt = txt[:100] + "..."
                        print(f"  {Colors.CYAN}→{Colors.RESET} {txt}")
                except:
                    print(f"{Colors.YELLOW}!{Colors.RESET} No hay registros TXT")
                
                # Registros CNAME
                try:
                    answers = dns.resolver.resolve(self.domain, 'CNAME')
                    print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} {Colors.BOLD}Registros CNAME:{Colors.RESET}")
                    for rdata in answers:
                        print(f"  {Colors.CYAN}→{Colors.RESET} {str(rdata)}")
                except:
                    pass
                
                # Intentar transferencia de zona (AXFR)
                self.try_zone_transfer()
                
            else:
                # Fallback usando socket
                try:
                    ip = socket.gethostbyname(self.domain)
                    self.ip_addresses.append(ip)
                    print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} {Colors.BOLD}IP del servidor:{Colors.RESET}")
                    print(f"  {Colors.CYAN}→{Colors.RESET} {ip}")
                except:
                    print(f"{Colors.RED}✗{Colors.RESET} No se pudo resolver el dominio")
        except Exception as e:
            print(f"{Colors.RED}✗{Colors.RESET} Error en resolución DNS: {str(e)}")
        
        Animations.print_end_section()
    
    def try_zone_transfer(self):
        """Intenta realizar transferencia de zona DNS"""
        print(f"\n{Colors.CYAN}[ZONE TRANSFER]{Colors.RESET} Intentando transferencia de zona...")
        if not DNS_AVAILABLE:
            print(f"{Colors.YELLOW}!{Colors.RESET} dnspython no disponible")
            return
        
        try:
            # Obtener servidores NS
            ns_servers = []
            try:
                answers = dns.resolver.resolve(self.domain, 'NS')
                for rdata in answers:
                    ns_servers.append(str(rdata))
            except:
                pass
            
            if not ns_servers:
                print(f"{Colors.YELLOW}!{Colors.RESET} No se encontraron servidores NS")
                return
            
            for ns in ns_servers:
                try:
                    # Resolver IP del servidor NS
                    ns_ip = socket.gethostbyname(ns)
                    print(f"{Colors.CYAN}→{Colors.RESET} Probando transferencia con {ns} ({ns_ip})...")
                    
                    # Intentar transferencia de zona
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, timeout=5))
                    
                    if zone:
                        print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} ¡Transferencia de zona exitosa!")
                        for name, node in zone.nodes.items():
                            for rdataset in node.rdatasets:
                                record_name = str(name)
                                record_value = str(rdataset)
                                if record_name.endswith('.'):
                                    record_name = record_name[:-1]
                                if record_name not in self.subdomains:
                                    self.subdomains.append(record_name)
                                    print(f"  {Colors.CYAN}→{Colors.RESET} {record_name}: {record_value}")
                    else:
                        print(f"{Colors.YELLOW}!{Colors.RESET} Transferencia de zona fallida en {ns}")
                except Exception as e:
                    error_text = str(e)[:80]
                    print(f"{Colors.YELLOW}!{Colors.RESET} Zone transfer: Not allowed / Failed")
                    print(f"  Result: {error_text or 'no response'}")
                    print(f"  Security impact: None established")
        except Exception as e:
            print(f"{Colors.RED}✗{Colors.RESET} Error en transferencia de zona: {str(e)[:50]}")
    
    def check_cloudflare(self):
        """Verifica si el sitio usa Cloudflare"""
        Animations.print_section("DETECCIÓN DE CLOUDFLARE")
        
        cloudflare_indicators = [
            'cloudflare', 'cf-ray', '__cfduid', 'cf-cache-status',
            'server: cloudflare', 'cf-connecting-ip', 'CF-RAY',
            'cf-request-id', 'cf-pseudo-ipv4'
        ]
        
        self.using_cloudflare = False
        self.cloudflare_evidence = []
        http_detection_available = False
        
        # Verificar headers
        if REQUESTS_AVAILABLE:
            try:
                response = self.session.get(self.target_url, timeout=self.request_timeout)
                if response is None:
                    raise requests.RequestException('HTTP response was empty')
                self.headers = dict(getattr(response, 'headers', None) or {})
                self.cookies = dict(getattr(response, 'cookies', None) or {})
                http_detection_available = bool(self.headers or self.cookies)
                
                print(f"{Colors.CYAN}→{Colors.RESET} Analizando headers HTTP...")
                for header, value in self.headers.items():
                    if any(indicator in header.lower() or indicator in str(value).lower() for indicator in cloudflare_indicators):
                        self.using_cloudflare = True
                        self.cloudflare_evidence.append(f'HTTP header: {header}')
                        print(f"{Colors.BRIGHT_RED}⚠ Cloudflare detectado:{Colors.RESET} {header}: {redact(value)}")
                
                if not self.using_cloudflare:
                    print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} No se detectó Cloudflare en los headers")
            except Exception as e:
                print(f"{Colors.YELLOW}!{Colors.RESET} No se pudo conectar para verificar Cloudflare: {str(e)}")
        
        # Verificar DNS
        if self.ip_addresses:
            print(f"\n{Colors.CYAN}→{Colors.RESET} Verificando rangos de IP de Cloudflare...")
            for ip in self.ip_addresses:
                if self.is_cloudflare_ip(ip):
                    self.using_cloudflare = True
                    self.cloudflare_evidence.append(f'Cloudflare IP range: {ip}')
                    print(f"{Colors.BRIGHT_RED}⚠{Colors.RESET} IP de Cloudflare detectada: {ip}")
        
        if self.using_cloudflare:
            print(f"\n{Colors.BRIGHT_GREEN}✓{Colors.RESET} Cloudflare proxy/CDN detectado")
            print(f"  Evidence: {', '.join(self.cloudflare_evidence) or 'unavailable'}")
            if not http_detection_available:
                print(f"  HTTP header detection: unavailable")
        else:
            status = 'No concluyente' if not http_detection_available and not self.ip_addresses else 'No detectado'
            print(f"\n{Colors.BRIGHT_YELLOW}?{Colors.RESET} Cloudflare: {status}")
        
        Animations.print_end_section()
    
    def is_cloudflare_ip(self, ip):
        """Verifica si una IP pertenece a Cloudflare"""
        cloudflare_ranges = [
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
            '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
            '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
            '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
        ]
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in cloudflare_ranges:
                if ip_obj in ipaddress.ip_network(cidr):
                    return True
        except:
            pass
        return False
    
    def find_real_ip(self):
        """Intenta encontrar la IP real del servidor detrás de Cloudflare"""
        Animations.print_section("BÚSQUEDA DE IP REAL")
        
        if not self.using_cloudflare:
            print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} No es necesario buscar IP real (no usa Cloudflare)")
            if self.ip_addresses:
                self.real_ip = self.ip_addresses[0]
                print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} IP del servidor: {self.real_ip}")
            Animations.print_end_section()
            return
        
        print(f"{Colors.BRIGHT_YELLOW}ℹ{Colors.RESET} Iniciando búsqueda de IP real...")
        print(f"{Colors.BRIGHT_YELLOW}ℹ{Colors.RESET} Métodos pasivos primero, luego fuerza bruta\n")
        
        methods = []
        
        # ===== MÉTODOS PASIVOS =====
        
        # Método 1: Buscar subdominios comunes que apunten directamente
        methods.append("Subdominios comunes")
        common_subdomains = ['mail', 'mx', 'mx1', 'mx2', 'smtp', 'webmail', 
                            'ftp', 'direct', 'origin', 'backend', 'server',
                            'host', 'ns1', 'ns2', 'cpanel', 'whm']
        
        print(f"{Colors.CYAN}[1/6]{Colors.RESET} Buscando subdominios comunes que puedan revelar IP...")
        if DNS_AVAILABLE:
            def resolve_subdomain(sub):
                full_domain = f"{sub}.{self.domain}"
                try:
                    answers = dns.resolver.resolve(full_domain, 'A')
                    return full_domain, [str(rdata) for rdata in answers]
                except Exception:
                    return full_domain, []

            with ThreadPoolExecutor(max_workers=10) as executor:
                results = executor.map(resolve_subdomain, common_subdomains)
                for full_domain, addresses in results:
                    for ip in addresses:
                        if not self.is_cloudflare_ip(ip):
                            print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} IP encontrada via {full_domain}: {ip}")
                            if not self.real_ip:
                                self.real_ip = ip
                                methods[0] = f"Subdominio {full_domain}"
                                break
        
        # Método 2: Registros MX
        print(f"{Colors.CYAN}[2/6]{Colors.RESET} Verificando registros MX...")
        if DNS_AVAILABLE and not self.real_ip:
            try:
                answers = dns.resolver.resolve(self.domain, 'MX')
                for rdata in answers:
                    mx_host = str(rdata.exchange)
                    try:
                        mx_ips = dns.resolver.resolve(mx_host, 'A')
                        for mx_ip in mx_ips:
                            ip = str(mx_ip)
                            if not self.is_cloudflare_ip(ip):
                                print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} IP del servidor de correo: {ip}")
                                if not self.real_ip:
                                    self.real_ip = ip
                    except:
                        pass
            except:
                pass
        
        # Método 3: Registros DNS históricos
        print(f"{Colors.CYAN}[3/6]{Colors.RESET} Verificando DNS histórico...")
        if not self.real_ip:
            historical_services = [
                f"https://api.hackertarget.com/hostsearch/?q={self.domain}",
                f"https://dns.bufferover.run/dns?q=.{self.domain}",
                f"https://crt.sh/?q=%25.{self.domain}&output=json"
            ]
            
            for service in historical_services:
                try:
                    if REQUESTS_AVAILABLE:
                        response = requests.get(service, timeout=self.request_timeout)
                        if response.status_code == 200:
                            if 'crt.sh' in service:
                                # Procesar JSON de crt.sh
                                try:
                                    certs = response.json()
                                    for cert in certs:
                                        if 'name_value' in cert:
                                            domains = cert['name_value'].split('\n')
                                            for domain in domains:
                                                if domain not in self.subdomains:
                                                    self.subdomains.append(domain)
                                except:
                                    pass
                            else:
                                lines = response.text.split('\n')
                                for line in lines[:20]:
                                    if line.strip() and ',' in line:
                                        parts = line.split(',')
                                        if len(parts) >= 2:
                                            ip = parts[1].strip()
                                            if ip and not self.is_cloudflare_ip(ip) and self.is_valid_ip(ip):
                                                print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} IP histórica encontrada: {ip}")
                                                if not self.real_ip:
                                                    self.real_ip = ip
                except:
                    pass
        
        # Método 4: Verificar certificado SSL
        print(f"{Colors.CYAN}[4/6]{Colors.RESET} Verificando certificado SSL...")
        if not self.real_ip:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=self.domain) as secure_sock:
                        cert = secure_sock.getpeercert()
                        if cert:
                            common_names = [
                                value
                                for attribute in cert.get('subject', ())
                                for key, value in attribute
                                if key == 'commonName'
                            ]
                            self.certificate_name = common_names[0] if common_names else None
                            if self.certificate_name:
                                print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} Certificado SSL obtenido (emitido para: {self.certificate_name})")
                                
                                # Resolver el commonName del certificado
                                try:
                                    cert_ips = socket.gethostbyname_ex(self.certificate_name)[2]
                                    for ip in cert_ips:
                                        if not self.is_cloudflare_ip(ip):
                                            print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} IP del certificado: {ip}")
                                            if not self.real_ip:
                                                self.real_ip = ip
                                except:
                                    pass
            except:
                pass
        
        # Método 5: Servicios de terceros
        print(f"{Colors.CYAN}[5/6]{Colors.RESET} Consultando servicios de terceros...")
        if not self.real_ip:
            third_party_services = [
                f"https://api.hackertarget.com/hostsearch/?q={self.domain}",
                f"https://dns.bufferover.run/dns?q={self.domain}",
                f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names",
                f"https://crt.sh/?q={self.domain}&output=json"
            ]
            
            def query_service(service):
                if not REQUESTS_AVAILABLE:
                    return service, []
                try:
                    response = requests.get(service, timeout=self.request_timeout)
                    if response.status_code != 200:
                        return service, []
                    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                    return service, [
                        ip for ip in re.findall(ip_pattern, response.text)
                        if not self.is_cloudflare_ip(ip) and self.is_valid_ip(ip)
                    ]
                except Exception:
                    return service, []

            with ThreadPoolExecutor(max_workers=4) as executor:
                for service, addresses in executor.map(query_service, third_party_services):
                    for ip in addresses:
                        print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} IP encontrada via {service.split('/')[2]}: {ip}")
                        if not self.real_ip:
                            self.real_ip = ip
        
        # ===== MÉTODO 6: FUERZA BRUTA DE SUBDOMINIOS =====
        if self.brute_force_enabled and not self.real_ip:
            print(f"\n{Colors.CYAN}[6/6]{Colors.RESET} {Colors.BRIGHT_YELLOW}Iniciando FUERZA BRUTA de subdominios...{Colors.RESET}")
            print(f"{Colors.BRIGHT_YELLOW}ℹ{Colors.RESET} Probando {len(self.subdomain_wordlist)} subdominios...")
            
            found_subdomains = []
            
            def brute_force_subdomain(sub):
                full_domain = f"{sub}.{self.domain}"
                try:
                    if DNS_AVAILABLE:
                        answers = dns.resolver.resolve(full_domain, 'A', lifetime=2)
                        ips = [str(rdata) for rdata in answers]
                        return full_domain, ips
                    else:
                        ips = socket.gethostbyname_ex(full_domain)[2]
                        return full_domain, ips
                except:
                    return full_domain, []
            
            # Usar ThreadPoolExecutor para fuerza bruta rápida
            total_subs = len(self.subdomain_wordlist)
            completed = 0
            found_count = 0
            
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {executor.submit(brute_force_subdomain, sub): sub for sub in self.subdomain_wordlist}
                
                for future in as_completed(futures):
                    completed += 1
                    full_domain, addresses = future.result()
                    
                    # Mostrar progreso
                    progress = f"[{completed}/{total_subs}]"
                    
                    if addresses:
                        found_count += 1
                        for ip in addresses:
                            if not self.is_cloudflare_ip(ip):
                                print(f"\r{Colors.BRIGHT_GREEN}✓{Colors.RESET} {progress} {Colors.BRIGHT_WHITE}{full_domain}{Colors.RESET} → {Colors.BRIGHT_GREEN}{ip}{Colors.RESET} (IP REAL)")
                                found_subdomains.append((full_domain, ip))
                                if not self.real_ip:
                                    self.real_ip = ip
                            else:
                                print(f"\r{Colors.CYAN}→{Colors.RESET} {progress} {full_domain} → {ip} (Cloudflare)")
                                found_subdomains.append((full_domain, ip))
                    else:
                        # Mostrar progreso sin spam
                        sys.stdout.write(f"\r{Colors.DIM}{progress} Probando: {full_domain}{Colors.RESET}")
                        sys.stdout.flush()
            
            print(f"\n{Colors.BRIGHT_GREEN}✓{Colors.RESET} Fuerza bruta completada: {found_count} subdominios encontrados")
            
            # Probar subdominios encontrados
            if found_subdomains and not self.real_ip:
                print(f"\n{Colors.BRIGHT_YELLOW}ℹ{Colors.RESET} Buscando IP real en subdominios encontrados...")
                for full_domain, ip in found_subdomains:
                    if not self.is_cloudflare_ip(ip):
                        print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} IP real via {full_domain}: {ip}")
                        if not self.real_ip:
                            self.real_ip = ip
        
        # ===== RESULTADO FINAL =====
        if self.real_ip:
            print(f"\n{Colors.BRIGHT_GREEN}╔══════════════════════════════════════════════╗{Colors.RESET}")
            print(f"{Colors.BRIGHT_GREEN}║  ✓✓ IP REAL DESCUBIERTA: {Colors.BRIGHT_WHITE}{self.real_ip}{Colors.BRIGHT_GREEN}  ║{Colors.RESET}")
            print(f"{Colors.BRIGHT_GREEN}╚══════════════════════════════════════════════╝{Colors.RESET}")
        else:
            print(f"\n{Colors.BRIGHT_YELLOW}╔══════════════════════════════════════════════╗{Colors.RESET}")
            print(f"{Colors.BRIGHT_YELLOW}║  ! No se pudo descubrir la IP real             ║{Colors.RESET}")
            print(f"{Colors.BRIGHT_YELLOW}╚══════════════════════════════════════════════╝{Colors.RESET}")
            print(f"\n{Colors.BRIGHT_YELLOW}ℹ{Colors.RESET} Sugerencias adicionales:")
            print(f"  {Colors.CYAN}•{Colors.RESET} Usar Shodan.io para buscar por dominio")
            print(f"  {Colors.CYAN}•{Colors.RESET} Buscar en Censys.io certificados históricos")
            print(f"  {Colors.CYAN}•{Colors.RESET} Verificar registros DNS antiguos en SecurityTrails")
            print(f"  {Colors.CYAN}•{Colors.RESET} Buscar en archivos de zona DNS públicos")
            print(f"  {Colors.CYAN}•{Colors.RESET} Intentar con nmap para escaneo de puertos")
        
        Animations.print_end_section()
    
    def is_valid_ip(self, ip):
        """Verifica si una IP es válida"""
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False
    
    def detect_technologies(self):
        """Detecta tecnologías usadas en el sitio web"""
        Animations.print_section("DETECCIÓN DE TECNOLOGÍAS")
        
        tech_patterns = {
            'WordPress': r'\b(?:wp-content|wp-includes|wp-json|wordpress)\b',
            'Joomla': r'\b(?:joomla|com_content)\b',
            'Drupal': r'\b(?:drupal|sites/default)\b',
            'PHP': r'\bphp(?:sessid)?\b|x-powered-by:\s*php',
            'ASP.NET': r'\basp\.net\b|__viewstate|x-aspnet-version|\.aspx\b',
            'Ruby on Rails': r'\b(?:ruby on rails|rails_env|_rails)\b',
            'Django': r'\b(?:django|csrfmiddlewaretoken)\b',
            'Laravel': r'\b(?:laravel|laravel_session)\b',
            'React': r'\breact(?:\.js|js)?\b|_react',
            'Angular': r'\bangular\b|ng-(?:app|version)',
            'Vue.js': r'\bvue(?:\.js|js)?\b|__vue__',
            'jQuery': r'\bjquery(?:\.js)?\b',
            'Bootstrap': r'\bbootstrap(?:\.min)?\.?(?:js|css)?\b',
            'Nginx': r'\bnginx\b',
            'Apache': r'\bapache\b',
            'IIS': r'\b(?:iis|microsoft-iis)\b',
            'Cloudflare': r'\bcloudflare\b|\bcf-ray\b|__cfduid|cf-cache-status',
            'Amazon CloudFront': r'\bcloudfront\b|x-amz-cf-id',
            'Google Cloud': r'\b(?:google cloud|gcloud|gcp)\b',
            'Docker': r'\bdocker\b',
            'Kubernetes': r'\b(?:kubernetes|k8s)\b',
            'Node.js': r'\b(?:node\.js|nodejs|express)\b|x-powered-by:\s*express',
            'Python': r'\b(?:python|werkzeug|flask)\b',
            'Java': r'\b(?:java|jsp|tomcat)\b|jsessionid',
            'MySQL': r'\bmysql\b',
            'PostgreSQL': r'\b(?:postgresql|psql)\b',
            'MongoDB': r'\bmongodb\b',
            'Redis': r'\bredis\b',
            'Memcached': r'\bmemcached\b',
            'Varnish': r'\bvarnish\b|x-varnish',
            'HAProxy': r'\bhaproxy\b',
            'Traefik': r'\btraefik\b',
            'Caddy': r'\bcaddy\b',
            'Jetty': r'\bjetty\b',
            'Lighttpd': r'\blighttpd\b',
            'Cherokee': r'\bcherokee\b',
        }
        
        detected_techs = []
        
        def detect_in_text(text, source):
            for tech, pattern in tech_patterns.items():
                if tech not in detected_techs and re.search(pattern, text, re.IGNORECASE):
                    detected_techs.append(tech)
                    print(f"  {Colors.BRIGHT_GREEN}✓{Colors.RESET} {tech} detectado en {source}")

        # Analizar headers
        print(f"{Colors.CYAN}[1/3]{Colors.RESET} Analizando headers HTTP...")
        for header, value in self.headers.items():
            detect_in_text(f"{header}: {value}", "headers")
        
        # Analizar cookies
        print(f"{Colors.CYAN}[2/3]{Colors.RESET} Analizando cookies...")
        for cookie_name, cookie_value in self.cookies.items():
            detect_in_text(f"{cookie_name}={cookie_value}", "cookies")
        
        # Analizar contenido HTML
        print(f"{Colors.CYAN}[3/3]{Colors.RESET} Analizando contenido HTML...")
        if REQUESTS_AVAILABLE and BS4_AVAILABLE:
            try:
                response = self.session.get(self.target_url, timeout=self.request_timeout)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                detect_in_text(response.text, "HTML")
                
                # Buscar scripts y links
                for tag in soup.find_all(['script', 'link', 'meta']):
                    detect_in_text(str(tag), "scripts/links")
            except:
                pass
        
        # Verificar tecnologías específicas de servidor
        if 'Server' in self.headers:
            print(f"  {Colors.CYAN}→{Colors.RESET} Server header: {self.headers['Server']}")
            detect_in_text(f"Server: {self.headers['Server']}", "headers")
        
        # Verificar X-Powered-By
        if 'X-Powered-By' in self.headers:
            powered_by = self.headers['X-Powered-By']
            print(f"  {Colors.CYAN}→{Colors.RESET} X-Powered-By: {powered_by}")
            detect_in_text(f"X-Powered-By: {powered_by}", "headers")
        
        self.technologies = list(set(detected_techs))
        
        if self.technologies:
            print(f"\n{Colors.BRIGHT_GREEN}✓{Colors.RESET} {Colors.BOLD}Tecnologías detectadas:{Colors.RESET}")
            for tech in sorted(self.technologies):
                print(f"  {Colors.CYAN}→{Colors.RESET} {tech}")
        else:
            print(f"{Colors.BRIGHT_YELLOW}!{Colors.RESET} No se detectaron tecnologías conocidas")
        
        Animations.print_end_section()
    
    def check_security_headers(self):
        """Evalúa headers modernos sin convertir ausencias en fallos críticos."""
        Animations.print_section("HEADERS DE SEGURIDAD")

        security_headers = {
            'Strict-Transport-Security': 'Protección contra downgrade de HTTPS',
            'Content-Security-Policy': 'Reduce XSS y carga de contenido no autorizado',
            'X-Content-Type-Options': 'Evita MIME sniffing',
            'X-Frame-Options': 'Reduce clickjacking en navegadores antiguos',
            'Referrer-Policy': 'Limita información enviada en Referer',
            'Permissions-Policy': 'Restringe APIs y capacidades del navegador'
        }
        
        self.security_headers = {}
        missing_headers = []
        
        for header, description in security_headers.items():
            if header in self.headers:
                self.security_headers[header] = self.headers[header]
                print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} {header}: {self.headers[header]}")
                print(f"  {Colors.DIM}{description}{Colors.RESET}")
            else:
                missing_headers.append(header)
                print(f"{Colors.BRIGHT_YELLOW}!{Colors.RESET} {header}: No presente")
                print(f"  {Colors.DIM}{description}{Colors.RESET}")
                self.add_finding(
                    'LOW', f'Missing {header}',
                    description,
                    f'{header} not present in the HTTPS response',
                    'Reduced browser-side defense in depth.',
                    f'Configure {header} according to the application policy.',
                    'High', status='Missing'
                )
        
        if missing_headers:
            print(f"\n{Colors.BRIGHT_YELLOW}⚠{Colors.RESET} {Colors.BOLD}Headers de seguridad faltantes:{Colors.RESET}")
            missing_headers_text = ', '.join(missing_headers)
            for line in Animations.wrap_text(missing_headers_text, width=78, subsequent_indent="    "):
                print(f"  {Colors.RED}{line}{Colors.RESET}")
            print(f"\n{Colors.BRIGHT_YELLOW}ℹ{Colors.RESET} Se recomienda implementar todos los headers de seguridad")
        
        print(f"\n{Colors.BOLD}Resultado:{Colors.RESET} {len(self.security_headers)}/{len(security_headers)} headers modernos presentes")
        print(f"{Colors.DIM}Las ausencias se reportan como observaciones LOW, no como vulnerabilidades confirmadas.{Colors.RESET}")
        
        Animations.print_end_section()
    
    def check_sql_injection(self):
        """Verifica vulnerabilidades SQL injection en formularios y parámetros"""
        Animations.print_section("DETECCIÓN DE SQL INJECTION")
        
        if not REQUESTS_AVAILABLE or not BS4_AVAILABLE:
            print(f"{Colors.YELLOW}!{Colors.RESET} Se requieren requests y beautifulsoup4 para esta prueba")
            Animations.print_end_section()
            return
        
        sql_payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR '1'='1' --",
            "\" OR \"1\"=\"1\" --",
            "' OR '1'='1' #",
            "' UNION SELECT NULL--",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--",
            "' AND 1=1--",
            "' AND 1=2--",
            "admin'--",
            "admin' #",
            "' OR 1=1--",
            "') OR ('1'='1",
            "' OR 'x'='x",
            "1; SELECT * FROM users",
            "1' AND SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--"
        ]
        
        sql_errors = [
            'SQL syntax', 'MySQL', 'ORA-', 'Oracle', 'PostgreSQL',
            'SQLite', 'Microsoft SQL', 'ODBC', 'JDBC', 'SQLSTATE',
            'Unclosed quotation mark', 'quoted string not properly terminated',
            'You have an error in your SQL syntax', 'Warning: mysql_',
            'PostgreSQL query failed', 'ODBC SQL Server Driver',
            'Microsoft OLE DB Provider for SQL Server', 'SQLite3::query',
            'pg_query(): Query failed', 'Fatal error: Uncaught PDOException'
        ]
        
        print(f"{Colors.CYAN}[1/2]{Colors.RESET} Analizando formularios HTML...")
        
        try:
            response = self.session.get(self.target_url, timeout=self.request_timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Encontrar formularios
            forms = soup.find_all('form')
            
            if not forms:
                print(f"{Colors.YELLOW}!{Colors.RESET} No se encontraron formularios en la página")
            else:
                print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} {len(forms)} formularios encontrados")
                
                for i, form in enumerate(forms):
                    form_action = form.get('action', self.target_url)
                    form_method = form.get('method', 'get').upper()
                    form_inputs = form.find_all(['input', 'textarea'])
                    
                    print(f"\n{Colors.CYAN}→{Colors.RESET} Formulario {i+1}: {form_method} {form_action}")
                    print(f"  {Colors.DIM}Inputs: {len(form_inputs)}{Colors.RESET}")
                    
                    # Probar cada input con payloads
                    for input_field in form_inputs:
                        input_name = input_field.get('name')
                        input_type = input_field.get('type', 'text')
                        
                        if input_name and input_type not in ['submit', 'button', 'image', 'file', 'hidden']:
                            for payload in sql_payloads[:5]:  # Probar solo 5 payloads para no ser muy agresivo
                                try:
                                    test_data = {}
                                    for inp in form_inputs:
                                        inp_name = inp.get('name')
                                        if inp_name:
                                            if inp_name == input_name:
                                                test_data[inp_name] = payload
                                            else:
                                                test_data[inp_name] = 'test'
                                    
                                    if form_method == 'POST':
                                        test_response = self.session.post(form_action, data=test_data, timeout=self.request_timeout)
                                    else:
                                        test_response = self.session.get(form_action, params=test_data, timeout=self.request_timeout)
                                    
                                    # Buscar errores SQL en la respuesta
                                    for error in sql_errors:
                                        if error.lower() in test_response.text.lower():
                                            print(f"{Colors.BRIGHT_YELLOW}! POSIBLE ERROR SQL (NO CONFIRMADO){Colors.RESET}")
                                            print(f"  {Colors.BRIGHT_WHITE}Campo: {input_name}{Colors.RESET}")
                                            print(f"  {Colors.BRIGHT_WHITE}Payload: [REDACTED TEST MARKER]{Colors.RESET}")
                                            print(f"  {Colors.BRIGHT_RED}Error detectado: {error}{Colors.RESET}")
                                            self.add_finding(
                                                'MEDIUM', 'Database error response observed',
                                                'A controlled test input produced a database error signature.',
                                                f'Field {input_name} triggered database error text: {error}',
                                                'The behavior may reveal unsafe input handling; SQL injection is not confirmed.',
                                                'Review parameterized queries and server-side error handling.',
                                                'Low', status='Potential; not confirmed'
                                            )
                                            break
                                except Exception as e:
                                    pass
        except Exception as e:
            print(f"{Colors.RED}✗{Colors.RESET} Error al analizar formularios: {str(e)}")
        
        print(f"\n{Colors.CYAN}[2/2]{Colors.RESET} Analizando parámetros GET...")
        
        try:
            # Obtener todos los links de la página
            response = self.session.get(self.target_url, timeout=self.request_timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            links_with_params = []
            for link in soup.find_all('a', href=True):
                href = link['href']
                if '?' in href:
                    full_url = urljoin(self.target_url, href)
                    links_with_params.append(full_url)
            
            if not links_with_params:
                print(f"{Colors.YELLOW}!{Colors.RESET} No se encontraron links con parámetros")
            else:
                print(f"{Colors.BRIGHT_GREEN}✓{Colors.RESET} {len(links_with_params)} links con parámetros encontrados")
                
                for link in links_with_params[:10]:  # Limitar a 10 links
                    parsed = urlparse(link)
                    params = urllib.parse.parse_qs(parsed.query)
                    
                    for param_name in params:
                        for payload in sql_payloads[:3]:  # Solo 3 payloads por parámetro
                            test_params = {param_name: payload}
                            for other_param in params:
                                if other_param != param_name:
                                    test_params[other_param] = 'test'
                            
                            try:
                                test_response = self.session.get(link.split('?')[0], params=test_params, timeout=self.request_timeout)
                                
                                for error in sql_errors:
                                    if error.lower() in test_response.text.lower():
                                        print(f"{Colors.BRIGHT_YELLOW}! POSIBLE ERROR SQL (NO CONFIRMADO){Colors.RESET}")
                                        print(f"  {Colors.BRIGHT_WHITE}URL: {link}{Colors.RESET}")
                                        print(f"  {Colors.BRIGHT_WHITE}Parámetro: {param_name}{Colors.RESET}")
                                        print(f"  {Colors.BRIGHT_WHITE}Payload: [REDACTED TEST MARKER]{Colors.RESET}")
                                        break
                            except:
                                pass
        except Exception as e:
            print(f"{Colors.RED}✗{Colors.RESET} Error al analizar parámetros GET: {str(e)}")
        
        Animations.print_end_section()


def main():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')

    parser = argparse.ArgumentParser(
        description='Analiza un sitio web que tengas permiso para probar.',
        epilog='Ejemplo: python web_scanner.py https://example.com --xss --waf --ssl --content'
    )
    parser.add_argument('target', help='URL objetivo')
    parser.add_argument('--brute-force', action='store_true', help='Activar fuerza bruta de subdominios')
    parser.add_argument('--wordlist', help='Wordlist personalizada')
    parser.add_argument('--workers', type=int, default=20, help='Workers (default: 20)')
    parser.add_argument('--scan-ports', action='store_true', help='Escanear puertos TCP')
    parser.add_argument('--port-timeout', type=float, default=2.0, help='Timeout por puerto')
    parser.add_argument('--sql', action='store_true', help='Ejecutar pruebas SQL activas y limitadas')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout requests')
    parser.add_argument('--output', help='Guardar JSON')
    # Nuevas opciones
    parser.add_argument('--xss', action='store_true', help='Probar XSS')
    parser.add_argument('--waf', action='store_true', help='Detectar WAF')
    parser.add_argument('--ssl', action='store_true', help='Analizar SSL/TLS')
    parser.add_argument('--content', action='store_true', help='Descubrir contenido')
    parser.add_argument('--backups', action='store_true', help='Buscar backups')
    parser.add_argument('--git', action='store_true', help='Buscar exposición .git')
    parser.add_argument('--apis', action='store_true', help='Descubrir APIs')
    parser.add_argument('--jwt', action='store_true', help='Analizar JWT')
    parser.add_argument('--default-creds', action='store_true', help='Probar credenciales por defecto (activo)')
    parser.add_argument('--all', action='store_true', help='Ejecutar módulos pasivos y de bajo impacto')
    
    args = parser.parse_args()
    
    target_url = args.target
    if not urlparse(target_url).scheme:
        target_url = f'https://{target_url}'
    
    Animations.print_banner()
    scanner = WebScanner(target_url)
    scanner.max_workers = args.workers
    scanner.request_timeout = args.timeout
    scanner.port_timeout = args.port_timeout
    
    if args.brute_force or args.wordlist:
        scanner.brute_force_enabled = True
        scanner.load_subdomain_wordlist(args.wordlist)
    
    # Ejecutar análisis base
    scanner.resolve_dns()
    scanner.check_cloudflare()
    scanner.find_real_ip()
    
    if args.scan_ports:
        target_ip = scanner.real_ip or (scanner.ip_addresses[0] if scanner.ip_addresses else None)
        if target_ip:
            scanner.port_scanner = PortScanner(target_ip, timeout=scanner.port_timeout, max_workers=scanner.max_workers)
            open_ports = scanner.port_scanner.scan()
            for port in open_ports:
                print(f"  {Colors.BRIGHT_GREEN}✓{Colors.RESET} {port}/tcp - {COMMON_PORTS[port]}")
    
    scanner.detect_technologies()
    scanner.check_security_headers()
    
    if args.sql:
        scanner.check_sql_injection()
    
    # Nuevas pruebas según flags
    if args.xss:
        scanner.check_xss()
    if args.waf or args.all:
        scanner.detect_waf()
    if args.ssl or args.all:
        scanner.check_ssl_tls()
    if args.content or args.all:
        scanner.discover_content()
    if args.backups or args.all:
        scanner.check_backup_files()
    if args.git or args.all:
        scanner.check_git_exposure()
    if args.apis or args.all:
        scanner.discover_apis()
    if args.jwt or args.all:
        scanner.test_jwt()
    if args.default_creds:
        scanner.check_default_credentials()
    
    # Resumen final
    Animations.print_separator(Colors.BRIGHT_GREEN)
    print(f"\n{Colors.BRIGHT_GREEN}╔══════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.BRIGHT_GREEN}║  ✓ ANÁLISIS COMPLETADO                       ║{Colors.RESET}")
    print(f"{Colors.BRIGHT_GREEN}╚══════════════════════════════════════════════╝{Colors.RESET}")
    
    print(f"\n{Colors.BOLD}Resumen del análisis:{Colors.RESET}")
    print(f"  {Colors.CYAN}→{Colors.RESET} Dominio: {scanner.domain}")
    print(f"  {Colors.CYAN}→{Colors.RESET} IPs: {', '.join(scanner.ip_addresses) if scanner.ip_addresses else 'N/A'}")
    print(f"  {Colors.CYAN}→{Colors.RESET} Cloudflare: {'Sí' if scanner.using_cloudflare else 'No'}")
    if scanner.cloudflare_evidence:
        print(f"  {Colors.CYAN}→{Colors.RESET} Cloudflare evidence: {', '.join(scanner.cloudflare_evidence)}")
    print(f"  {Colors.CYAN}→{Colors.RESET} WAF: {scanner.waf_status}")
    print(f"  {Colors.CYAN}→{Colors.RESET} IP real: {scanner.real_ip if scanner.real_ip else 'No descubierta'}")
    print(f"  {Colors.CYAN}→{Colors.RESET} Tecnologías: {len(scanner.technologies)}")
    print(f"  {Colors.CYAN}→{Colors.RESET} Headers modernos: {len(scanner.security_headers)}/6")
    if scanner.port_scanner:
        print(f"  {Colors.CYAN}→{Colors.RESET} Puertos abiertos: {len(scanner.port_scanner.open_ports)}")

    severity_counts = {severity: 0 for severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')}
    for finding in scanner.findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
    print(f"\n{Colors.BOLD}Security Assessment:{Colors.RESET}")
    print('  ' + ' | '.join(f'{severity}: {severity_counts[severity]}' for severity in severity_counts))
    if scanner.findings:
        for finding in scanner.findings:
            print(f"  [{finding.severity}] {finding.title}")
            print(f"    Confidence: {finding.confidence}")
            print(f"    Status: {finding.status}")
            print(f"    Evidence: {finding.evidence}")
    else:
        print(f"  {Colors.GREEN}No se registraron hallazgos con evidencia suficiente.{Colors.RESET}")
    
    if args.output:
        try:
            results = {
                'timestamp': datetime.now().isoformat(),
                'domain': scanner.domain,
                'ip_addresses': scanner.ip_addresses,
                'using_cloudflare': scanner.using_cloudflare,
                'cloudflare_evidence': scanner.cloudflare_evidence,
                'waf_status': scanner.waf_status,
                'real_ip': scanner.real_ip,
                'technologies': scanner.technologies,
                'security_headers': scanner.security_headers,
                'subdomains': scanner.subdomains[:50],
                'certificate_name': scanner.certificate_name,
                'open_ports': scanner.port_scanner.open_ports if scanner.port_scanner else [],
                'findings': [asdict(finding) for finding in scanner.findings]
            }
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"\n{Colors.BRIGHT_GREEN}✓{Colors.RESET} Resultados guardados en: {args.output}")
        except Exception as e:
            print(f"\n{Colors.RED}✗{Colors.RESET} Error guardando JSON: {str(e)}")
    
    print(f"\n{Colors.BRIGHT_YELLOW}⚠{Colors.RESET} {Colors.DIM}Recuerda: Solo audita sitios con permiso explícito.{Colors.RESET}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.BRIGHT_YELLOW}⚠{Colors.RESET} Análisis interrumpido")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n{Colors.BRIGHT_RED}✗{Colors.RESET} Error fatal: {str(e)}")
        sys.exit(1)