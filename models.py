"""Modelos de datos independientes de la interfaz y del transporte."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
CONFIDENCES = ('HIGH', 'MEDIUM', 'LOW')


@dataclass(frozen=True)
class Finding:
    """Un hallazgo observado: nunca una vulnerabilidad asumida."""
    severity: str
    title: str
    description: str
    evidence: str
    impact: str
    recommendation: str
    confidence: str
    status: str = 'Observed'

    def __post_init__(self) -> None:
        object.__setattr__(self, 'severity', self.severity.upper())
        object.__setattr__(self, 'confidence', self.confidence.upper())
        if self.severity not in SEVERITIES:
            raise ValueError(f'Invalid severity: {self.severity}')
        if self.confidence not in CONFIDENCES:
            raise ValueError(f'Invalid confidence: {self.confidence}')

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Resultado transportable a consola, JSON, PDF o interfaz gráfica."""
    target: str
    started_at: str
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    completed_at: str | None = None
    errors: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def counts(self) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITIES}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    @property
    def risk_level(self) -> str:
        counts = self.counts()
        for severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            if counts[severity]:
                return severity
        return 'INFO'

    def to_dict(self) -> dict[str, Any]:
        return {
            'target': self.target,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'risk_level': self.risk_level,
            'counts': self.counts(),
            'findings': [finding.to_dict() for finding in self.findings],
            'metadata': self.metadata,
            'errors': self.errors,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'ScanResult':
        """Reconstruye un resultado guardado sin depender de la interfaz."""
        findings = [Finding(**item) for item in data.get('findings', [])]
        return cls(
            target=str(data.get('target', 'Unknown target')),
            started_at=str(data.get('started_at', '')),
            completed_at=data.get('completed_at'),
            findings=findings,
            metadata=dict(data.get('metadata', {})),
            errors=[str(error) for error in data.get('errors', [])],
        )
