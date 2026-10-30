"""JSON-lines adapter used by the native Qt Widgets application."""

from __future__ import annotations

import json
import logging
import os
import sys
import traceback
from pathlib import Path
from typing import Any

from .config import ScannerConfig, normalize_target
from .engine import DefensiveScanner
from .models import ScanResult
from .reporting import export_json, export_pdf
from .storage import AppSettings, LocalStore

logger = logging.getLogger(__name__)
ALLOWED_MODULES = frozenset({"dns", "http", "headers", "tls"})


def _store() -> LocalStore:
    return LocalStore(Path.cwd() / ".scanner")


def handle_request(request: dict[str, Any]) -> dict[str, Any]:
    """Dispatch one validated request and return a JSON-serializable response."""
    request_id = request.get("id")
    operation = request.get("operation")
    try:
        if operation == "scan":
            return _scan(request, request_id)
        if operation == "history":
            records = _store().list_results()
            return {
                "id": request_id,
                "ok": True,
                "records": [
                    {
                        "path": str(path.resolve()),
                        "result": _result_payload(result),
                        "executive_summary": summary,
                    }
                    for path, result, summary in records
                ],
            }
        if operation == "settings.load":
            from dataclasses import asdict

            return {"id": request_id, "ok": True, "settings": asdict(_store().load_settings())}
        if operation == "settings.save":
            settings = AppSettings(**request.get("settings", {}))
            settings.validate()
            _store().save_settings(settings)
            return {"id": request_id, "ok": True}
        if operation in {"export.json", "export.pdf"}:
            result = ScanResult.from_dict(_required_object(request, "result"))
            destination = _required_string(request, "destination")
            summary = request.get("executive_summary")
            if operation == "export.json":
                path = export_json(result, destination)
            else:
                path = export_pdf(result, destination, executive_summary=summary)
            return {"id": request_id, "ok": True, "path": str(path.resolve())}
        if operation == "history.delete":
            path = Path(_required_string(request, "path")).resolve()
            _store().delete_result(path)
            return {"id": request_id, "ok": True}
        if operation == "history.update":
            path = Path(_required_string(request, "path")).resolve()
            result = ScanResult.from_dict(_required_object(request, "result"))
            summary = _required_string(request, "executive_summary")
            _store().update_result(path, result, summary)
            return {"id": request_id, "ok": True}
        if operation == "history.clear":
            count = _store().clear_history()
            return {"id": request_id, "ok": True, "deleted": count}
        if operation in {"ai.summary", "ai.chat"}:
            return _ai_request(request, request_id, operation)
        if operation == "ai.status":
            from .ai import ollama_status

            status = ollama_status()
            configured = bool(os.getenv("SCANNER_GEMINI_API_KEY") or os.getenv("GEMINI_API_KEY"))
            return {
                "id": request_id,
                "ok": True,
                "gemini_configured": configured,
                "ollama_available": status.available,
                "ollama_message": status.message,
            }
        raise ValueError(f"Unsupported operation: {operation!r}")
    except (KeyError, TypeError, ValueError, OSError, RuntimeError) as error:
        return {"id": request_id, "ok": False, "error": str(error)}
    except Exception as error:
        logger.exception("Unexpected bridge failure for operation %r", operation)
        return {"id": request_id, "ok": False, "error": f"{type(error).__name__}: {error}"}


def _scan(request: dict[str, Any], request_id: Any) -> dict[str, Any]:
    target = normalize_target(_required_string(request, "target"))
    modules_value = request.get("modules", ["dns", "http", "headers", "tls"])
    if not isinstance(modules_value, list) or not modules_value:
        raise ValueError("Select at least one scanner module.")
    modules = tuple(dict.fromkeys(str(name) for name in modules_value))
    invalid = set(modules) - ALLOWED_MODULES
    if invalid:
        raise ValueError(f"Unsupported scanner modules: {', '.join(sorted(invalid))}")

    settings = AppSettings(
        timeout=float(request.get("timeout", 10.0)),
        rate_limit=float(request.get("rate_limit", 0.0)),
        max_redirects=int(request.get("max_redirects", 5)),
    )
    settings.validate()
    config = ScannerConfig(
        target,
        timeout=settings.timeout,
        rate_limit=settings.rate_limit,
        max_redirects=settings.max_redirects,
    )

    def report_progress(label: str, step: int, total: int) -> None:
        _write_message(
            {
                "event": "progress",
                "id": request_id,
                "label": label,
                "step": step,
                "total": total,
            }
        )

    result = DefensiveScanner(config, report_progress).run(modules)
    path = _store().save_result(result)
    return {
        "id": request_id,
        "ok": True,
        "result": _result_payload(result),
        "history_path": str(path.resolve()),
    }


def _ai_request(
    request: dict[str, Any],
    request_id: Any,
    operation: str,
) -> dict[str, Any]:
    from .ai import generate_summary, karen_reply

    result_data = request.get("result")
    result = ScanResult.from_dict(result_data) if isinstance(result_data, dict) else None
    if operation == "ai.summary":
        summary = generate_summary(
            result,
            ollama_model=request.get("ollama_model"),
        )
        return {"id": request_id, "ok": True, "summary": summary}

    history_value = request.get("history", [])
    if not isinstance(history_value, list):
        raise ValueError("Chat history must be a list.")
    history = [
        (("Usuario" if str(item[0]) == "user" else "Karen"), str(item[1]))
        for item in history_value
        if isinstance(item, list) and len(item) == 2
    ]
    answer = karen_reply(
        _required_string(request, "question"),
        result=result,
        history=history,
        ollama_model=request.get("ollama_model"),
    )
    return {"id": request_id, "ok": True, "answer": answer}


def _required_string(request: dict[str, Any], key: str) -> str:
    value = request.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Missing or empty field: {key}")
    return value.strip()


def _result_payload(result: ScanResult) -> dict[str, Any]:
    payload = result.to_dict()
    payload["metadata"]["finding_modules"] = [
        _finding_module(finding.title) for finding in result.findings
    ]
    return payload


def _finding_module(title: str) -> str:
    normalized = title.casefold()
    if "header" in normalized:
        return "headers"
    if "tls" in normalized or "certificado" in normalized or "certificate" in normalized:
        return "tls"
    if "dns" in normalized or "resolución" in normalized:
        return "dns"
    if any(marker in normalized for marker in ("http", "servidor", "cdn", "proxy")):
        return "http"
    return "general"


def _required_object(request: dict[str, Any], key: str) -> dict[str, Any]:
    value = request.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"Missing or invalid object field: {key}")
    return value


def _write_message(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main() -> int:
    logging.basicConfig(stream=sys.stderr, level=logging.ERROR)
    for line_number, line in enumerate(sys.stdin, start=1):
        if not line.strip():
            continue
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("Each request must be a JSON object.")
            response = handle_request(request)
        except (json.JSONDecodeError, ValueError) as error:
            logger.error("Invalid bridge request on line %d: %s", line_number, error)
            response = {"id": None, "ok": False, "error": str(error)}
        except Exception as error:
            logger.error("Unexpected bridge error: %s\n%s", error, traceback.format_exc())
            response = {"id": None, "ok": False, "error": f"{type(error).__name__}: {error}"}
        _write_message(response)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
