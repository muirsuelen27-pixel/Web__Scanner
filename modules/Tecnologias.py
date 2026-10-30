from __future__ import annotations

import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class Technology:
    name: str
    category: str
    evidence: str
    confidence: str


def detect_technologies(
    headers: dict[str, str],
    html: str,
) -> list[Technology]:
    findings: list[Technology] = []

    normalized_headers = {
        name.lower(): str(value).lower()
        for name, value in headers.items()
    }
    html_lower = html.lower()

    server_header = normalized_headers.get("server", "")
    if "nginx" in server_header:
        findings.append(
            Technology(
                name="Nginx",
                category="Servidor Web",
                evidence=f"Header 'Server': {server_header}",
                confidence="Alta",
            )
        )
    elif "apache" in server_header:
        findings.append(
            Technology(
                name="Apache",
                category="Servidor Web",
                evidence=f"Header 'Server': {server_header}",
                confidence="Alta",
            )
        )

    language_markers = (
        ("php", "PHP"),
        ("python", "Python"),
        ("ruby", "Ruby"),
        ("node.js", "Node.js"),
        ("nodejs", "Node.js"),
    )

    detected_languages: set[str] = set()
    for marker, name in language_markers:
        if marker in html_lower and name not in detected_languages:
            findings.append(
                Technology(
                    name=name,
                    category="Lenguaje de Programación",
                    evidence=f"Se encontró '{marker}' en el contenido HTML",
                    confidence="Media",
                )
            )
            detected_languages.add(name)

    if not findings:
        findings.append(
            Technology(
                name="Desconocido",
                category="Desconocido",
                evidence="No se detectaron tecnologías conocidas",
                confidence="Baja",
            )
        )

    return findings


def confirm_technologies(
    headers: dict[str, str],
    html: str,
    technologies: list[Technology],
) -> list[Technology]:
    if not technologies:
        return []

    normalized_headers = {
        name.lower(): str(value).lower()
        for name, value in headers.items()
    }
    html_lower = html.lower()
    server_header = normalized_headers.get("server", "")

    confirmed: list[Technology] = []

    for tech in technologies:
        if tech.name == "Desconocido":
            confirmed.append(tech)
            continue

        if tech.name == "Nginx" and "nginx" in server_header:
            confirmed.append(tech)
        elif tech.name == "Apache" and "apache" in server_header:
            confirmed.append(tech)
        elif tech.name == "PHP" and "php" in html_lower:
            confirmed.append(tech)
        elif tech.name == "Python" and "python" in html_lower:
            confirmed.append(tech)
        elif tech.name == "Ruby" and "ruby" in html_lower:
            confirmed.append(tech)
        elif tech.name == "Node.js" and (
            "node.js" in html_lower or "nodejs" in html_lower
        ):
            confirmed.append(tech)

    if not confirmed and any(tech.name == "Desconocido" for tech in technologies):
        return [tech for tech in technologies if tech.name == "Desconocido"]

    return confirmed


def render_technologies(technologies: list[Technology]) -> str:
    if not technologies:
        return "No se detectaron tecnologías."

    lines = ["Tecnologías detectadas:"]
    for tech in technologies:
        lines.append(
            f"- {tech.name} ({tech.category}) - Evidencia: {tech.evidence} - "
            f"Confianza: {tech.confidence}"
        )
    return "\n".join(lines)


def process_technologies(response) -> list[Technology]:
    try:
        technologies = detect_technologies(response.headers, response.text)
        confirmed_technologies = confirm_technologies(
            response.headers,
            response.text,
            technologies,
        )
        result = confirmed_technologies or technologies
        print(render_technologies(result))
        return result
    except Exception as error:
        print(f"Error al detectar tecnologías: {error}", file=sys.stderr)
        print(f"Encabezados HTTP: {response.headers}", file=sys.stderr)
        return []