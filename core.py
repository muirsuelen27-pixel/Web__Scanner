"""Orquestación incremental sobre el scanner CLI existente."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from .models import Finding, ScanResult


class ScannerEngine:
    """Adapta un WebScanner existente a resultados reutilizables.

    No reemplaza WebScanner: permite migrar módulos gradualmente sin romper la
    interfaz CLI actual.
    """

    def __init__(self, scanner: Any):
        self.scanner = scanner

    def run(self, modules: list[str] | None = None) -> ScanResult:
        selected = modules or []
        result = ScanResult(
            target=self.scanner.target_url,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        for module_name in selected:
            operation: Callable[[], Any] | None = getattr(self.scanner, module_name, None)
            if operation is None:
                result.findings.append(Finding(
                    'INFO', f'Module unavailable: {module_name}',
                    'The requested module is not available in this installation.',
                    module_name, 'No impact established.',
                    'Install the complete project and retry.', 'HIGH', 'Not run'
                ))
                continue
            try:
                operation()
            except Exception as error:  # module isolation boundary
                result.findings.append(Finding(
                    'INFO', f'Module failed: {module_name}',
                    'The module failed without stopping the complete scan.',
                    type(error).__name__, 'No global impact established.',
                    'Review the module log and retry with a longer timeout.',
                    'HIGH', 'Error'
                ))
        for raw_finding in getattr(self.scanner, 'findings', []):
            if isinstance(raw_finding, Finding):
                result.add(raw_finding)
                continue
            result.add(Finding(
                severity=getattr(raw_finding, 'severity', 'INFO'),
                title=getattr(raw_finding, 'title', 'Legacy finding'),
                description=getattr(raw_finding, 'description', ''),
                evidence=getattr(raw_finding, 'evidence', ''),
                impact=getattr(raw_finding, 'impact', 'No impact established.'),
                recommendation=getattr(raw_finding, 'recommendation', 'Review manually.'),
                confidence=getattr(raw_finding, 'confidence', 'LOW'),
                status=getattr(raw_finding, 'status', 'Observed'),
            ))
        result.metadata.update({
            'cloudflare': getattr(self.scanner, 'using_cloudflare', False),
            'waf_status': getattr(self.scanner, 'waf_status', 'Not conclusive'),
            'technologies': getattr(self.scanner, 'technologies', []),
        })
        result.completed_at = datetime.now(timezone.utc).isoformat()
        return result
