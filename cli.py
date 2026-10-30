"""Interfaz de consola del motor defensivo moderno."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from .ai import DEFAULT_GEMINI_MODEL, LocalAIError, generate_summary
from .config import ScannerConfig, normalize_target
from .engine import DefensiveScanner
from .reporting import export_json, export_pdf, render_summary


SAFE_MODULES = ('dns', 'http', 'headers', 'tls')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='web_scanner.py',
        description='Auditoría web defensiva, basada en evidencia y de bajo impacto.',
    )
    parser.add_argument('target', nargs='?', help='URL http(s) autorizada a evaluar')
    parser.add_argument('--gui', action='store_true', help='Abrir la interfaz gráfica profesional')
    parser.add_argument('--modules', nargs='+', choices=SAFE_MODULES, default=list(SAFE_MODULES),
                        help='Módulos seguros a ejecutar (por defecto: todos)')
    parser.add_argument('--workers', type=int, default=20, help='Límite reservado para extensiones (1-100)')
    parser.add_argument('--timeout', type=float, default=10.0, help='Timeout de red en segundos')
    parser.add_argument('--rate-limit', type=float, default=0.0, help='Segundos mínimos entre solicitudes')
    parser.add_argument('--max-redirects', type=int, default=5, help='Máximo de redirecciones HTTP')
    parser.add_argument('--output', metavar='ARCHIVO', help='Exportar resultado JSON')
    parser.add_argument('--pdf', metavar='ARCHIVO', help='Exportar informe PDF')
    parser.add_argument('--ai-summary', action='store_true', help='Añadir un resumen redactado por Gemini (Ollama opcional como respaldo)')
    parser.add_argument('--ollama-model', help='Modelo local de Ollama como respaldo opcional; por defecto qwen2.5:3b')
    parser.add_argument('--legacy', action='store_true', help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.legacy:
        parser.error('--legacy solo está disponible desde web_scanner.py')
    if args.gui:
        cpp_root = Path(__file__).parent / 'cpp' / 'build'
        candidates = (
            cpp_root / 'web_scanner.exe',
            cpp_root / 'Debug' / 'web_scanner.exe',
            cpp_root / 'Release' / 'web_scanner.exe',
            cpp_root / 'web_scanner',
        )
        executable = next((path for path in candidates if path.is_file()), None)
        if executable:
            command = [str(executable)]
            if args.target:
                command.extend(['--target', args.target])
            return subprocess.run(command, check=False).returncode
        from .gui import launch
        return launch(args.target or '', args.output)
    if not args.target:
        parser.error('indica una URL objetivo o utiliza --gui')
    try:
        config = ScannerConfig(
            normalize_target(args.target), workers=args.workers, timeout=args.timeout,
            rate_limit=args.rate_limit, max_redirects=args.max_redirects,
        )
    except ValueError as error:
        parser.error(str(error))
    result = DefensiveScanner(
        config,
        progress=lambda label, step, total: print(f'[{step}/{total}] {label}') if step < total else None,
    ).run(tuple(args.modules))
    print(render_summary(result))
    summary: str | None = None
    if args.ai_summary:
        try:
            summary = generate_summary(
                result,
                model=DEFAULT_GEMINI_MODEL,
                ollama_model=args.ollama_model,
            )
            print('\nResumen ejecutivo:\n' + summary)
        except LocalAIError as error:
            print(f'\nIA no disponible: {error}', file=sys.stderr)
    if args.output:
        path = export_json(result, args.output)
        print(f'\nJSON guardado en: {path}')
    if args.pdf:
        path = export_pdf(result, args.pdf, executive_summary=summary)
        print(f'PDF guardado en: {path}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
