"""Persistencia local del scanner: ajustes e historial, nunca secretos."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .models import ScanResult


@dataclass
class AppSettings:
    timeout: float = 10.0
    rate_limit: float = 0.0
    max_redirects: int = 5
    ollama_model: str = 'qwen2.5:3b'
    accent: str = 'cyan'
    auto_ai_summary: bool = False

    def validate(self) -> None:
        if not 1 <= self.timeout <= 120:
            raise ValueError('El timeout debe estar entre 1 y 120 segundos.')
        if not 0 <= self.rate_limit <= 30:
            raise ValueError('El rate limit debe estar entre 0 y 30 segundos.')
        if not 0 <= self.max_redirects <= 20:
            raise ValueError('Las redirecciones deben estar entre 0 y 20.')
        if self.accent not in {'cyan', 'indigo', 'emerald'}:
            raise ValueError('El color de acento no es válido.')


class LocalStore:
    """Guarda datos de la aplicación en .scanner/, excluida de Git."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root or Path.cwd() / '.scanner')
        self.history_dir = self.root / 'history'
        self.settings_path = self.root / 'settings.json'

    def load_settings(self) -> AppSettings:
        try:
            payload = json.loads(self.settings_path.read_text(encoding='utf-8'))
            settings = AppSettings(**payload)
            settings.validate()
            return settings
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return AppSettings()

    def save_settings(self, settings: AppSettings) -> None:
        settings.validate()
        self.root.mkdir(parents=True, exist_ok=True)
        self.settings_path.write_text(json.dumps(asdict(settings), indent=2), encoding='utf-8')

    def save_result(self, result: ScanResult, executive_summary: str | None = None) -> Path:
        self.history_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        safe_target = ''.join(char if char.isalnum() else '_' for char in result.target)[:48].strip('_')
        path = self.history_dir / f'{timestamp}_{safe_target or "scan"}.json'
        payload = result.to_dict()
        if executive_summary:
            payload['executive_summary'] = executive_summary
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
        return path

    def list_results(self) -> list[tuple[Path, ScanResult, str | None]]:
        records: list[tuple[Path, ScanResult, str | None]] = []
        if not self.history_dir.exists():
            return records
        for path in sorted(self.history_dir.glob('*.json'), reverse=True):
            try:
                payload = json.loads(path.read_text(encoding='utf-8'))
                records.append((path, ScanResult.from_dict(payload), payload.get('executive_summary')))
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue
        return records

    def update_result(self, path: Path, result: ScanResult, executive_summary: str | None) -> None:
        """Actualiza un registro ya existente al añadir un resumen local."""
        if path.parent != self.history_dir:
            raise ValueError('El registro no pertenece al historial local.')
        payload = result.to_dict()
        if executive_summary:
            payload['executive_summary'] = executive_summary
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')

    def delete_result(self, path: Path) -> None:
        """Elimina únicamente un informe ubicado en el historial de la aplicación."""
        if path.parent != self.history_dir or path.suffix.lower() != '.json':
            raise ValueError('El registro no pertenece al historial local.')
        path.unlink(missing_ok=True)

    def clear_history(self) -> int:
        """Elimina informes locales y devuelve la cantidad eliminada."""
        if not self.history_dir.exists():
            return 0
        records = list(self.history_dir.glob('*.json'))
        for path in records:
            path.unlink()
        return len(records)
