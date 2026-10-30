"""Integración local con Ollama para redactar, no para decidir riesgo."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .models import ScanResult

DEFAULT_ENDPOINT = 'http://127.0.0.1:11434'
DEFAULT_MODEL = 'qwen2.5:3b'
DEFAULT_GEMINI_MODEL = 'gemini-flash-lite-latest'
UNSUPPORTED_CLAIM_STEMS = ('vulnerab', 'ataque', 'exploit', 'brecha', 'intrusi', 'compromiso')


def _gemini_error_message(error: HTTPError | URLError | Exception) -> str:
    if isinstance(error, HTTPError):
        try:
            text = error.read().decode('utf-8', errors='replace').strip()
        except Exception:
            text = ''
        return f'Gemini API respondió HTTP {error.code}: {text or "sin detalle del servicio."}'
    if isinstance(error, URLError):
        reason = getattr(error, 'reason', error)
        return f'Gemini no pudo conectarse al servicio: {reason}'
    return f'Gemini devolvió un error inesperado: {error}'


class LocalAIError(RuntimeError):
    """Ollama no está instalado, iniciado o no tiene el modelo seleccionado."""


@dataclass(frozen=True)
class OllamaStatus:
    available: bool
    models: tuple[str, ...] = ()
    message: str = ''


def ollama_status(endpoint: str | None = None) -> OllamaStatus:
    """Comprueba Ollama local sin enviar resultados de auditoría."""
    base_url = (endpoint or os.getenv('SCANNER_OLLAMA_ENDPOINT') or DEFAULT_ENDPOINT).rstrip('/')
    try:
        with urlopen(f'{base_url}/api/tags', timeout=3) as response:
            payload = json.loads(response.read().decode('utf-8'))
    except (OSError, URLError, json.JSONDecodeError):
        return OllamaStatus(False, message='Ollama local no responde en el puerto 11434.')
    models = tuple(item.get('name', '') for item in payload.get('models', []) if item.get('name'))
    return OllamaStatus(True, models=models, message='Ollama local está disponible.')


def grounded_summary(result: ScanResult) -> str:
    """Resumen determinista para que ningún modelo pueda alterar los hechos."""
    counts = result.counts()
    total = len(result.findings)
    observed = [finding for finding in result.findings if finding.status == 'Observed']
    missing = [finding for finding in result.findings if finding.status == 'Missing']
    pieces = [
        f'El análisis defensivo de {result.target} registró {total} hallazgo(s).',
        f'El nivel más alto observado es {result.risk_level}.',
        'Distribución: ' + ', '.join(f'{severity} {counts[severity]}' for severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')) + '.',
    ]
    if missing:
        pieces.append(f'{len(missing)} hallazgo(s) corresponde(n) a configuración ausente observada; requieren revisión manual antes de concluir impacto.')
    if observed:
        pieces.append(f'{len(observed)} elemento(s) se registró/registraron como evidencia informativa u observada.')
    if result.errors:
        pieces.append('Algunos módulos no fueron concluyentes; el informe conserva esa limitación.')
    pieces.append('El resultado no confirma vulnerabilidades por sí solo.')
    return ' '.join(pieces)


def _contains_unsupported_claim(summary: str, result: ScanResult) -> bool:
    """Rechaza afirmaciones de ataque que no estén presentes en la evidencia de entrada."""
    source = json.dumps(result.to_dict(), ensure_ascii=False).lower()
    generated = summary.lower()
    return any(stem in generated and stem not in source for stem in UNSUPPORTED_CLAIM_STEMS)


def local_summary(
    result: ScanResult,
    model: str | None = None,
    endpoint: str | None = None,
) -> str:
    """Genera un resumen local; no permite que la IA altere los hallazgos."""
    base_url = (endpoint or os.getenv('SCANNER_OLLAMA_ENDPOINT') or DEFAULT_ENDPOINT).rstrip('/')
    selected_model = model or os.getenv('SCANNER_OLLAMA_MODEL') or DEFAULT_MODEL
    status = ollama_status(base_url)
    if not status.available:
        raise LocalAIError(status.message)
    if selected_model not in status.models:
        available = ', '.join(status.models) or 'ninguno'
        raise LocalAIError(
            f'El modelo {selected_model!r} no está disponible. Modelos instalados: {available}. '
            f'Ejecuta: ollama pull {selected_model}'
        )
    prompt = (
        'Eres un asistente de redacción para un informe de seguridad defensiva. '
        'Reescribe el borrador proporcionado en español claro, en máximo 180 palabras. '
        'No añadas hechos, ejemplos, causas, ataques, vulnerabilidades, impactos ni recomendaciones que no estén escritos en el borrador. '
        'No uses palabras como ataque, exploit, brecha o vulnerabilidad a menos que aparezcan literalmente en el borrador. '
        'Devuelve sólo el resumen, sin título.\n\nBORRADOR VERIFICADO:\n' + grounded_summary(result)
    )
    body = json.dumps({
        'model': selected_model, 'prompt': prompt, 'stream': False,
        'options': {'temperature': 0.2, 'num_predict': 300},
    }).encode('utf-8')
    request = Request(
        f'{base_url}/api/generate',
        data=body,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urlopen(request, timeout=90) as response:
            payload = json.loads(response.read().decode('utf-8'))
    except (OSError, URLError, json.JSONDecodeError) as error:
        raise LocalAIError('Ollama no pudo generar el resumen local.') from error
    summary = str(payload.get('response', '')).strip()
    if not summary:
        raise LocalAIError('Ollama devolvió un resumen vacío.')
    if _contains_unsupported_claim(summary, result):
        return grounded_summary(result)
    return summary


def gemini_summary(
    result: ScanResult,
    model: str = DEFAULT_GEMINI_MODEL,
    api_key: str | None = None,
) -> str:
    """Genera un resumen usando Gemini cuando existe una clave válida."""
    selected_key = (api_key or os.getenv('SCANNER_GEMINI_API_KEY') or os.getenv('GEMINI_API_KEY') or '').strip()
    if not selected_key:
        raise LocalAIError(
            'No se proporcionó la clave de API de Gemini. Configura SCANNER_GEMINI_API_KEY o GEMINI_API_KEY.'
        )

    prompt = (
        'Eres un asistente de redacción para un informe de seguridad defensiva. '
        'Reescribe el borrador proporcionado en español claro, en máximo 180 palabras. '
        'No añadas hechos, ejemplos, causas, ataques, vulnerabilidades, impactos ni recomendaciones que no estén escritos en el borrador. '
        'No uses palabras como ataque, exploit, brecha o vulnerabilidad a menos que aparezcan literalmente en el borrador. '
        'Devuelve sólo el resumen, sin título.\n\nBORRADOR VERIFICADO:\n' + grounded_summary(result)
    )

    body = json.dumps({
        'contents': [
            {
                'parts': [
                    {'text': prompt}
                ]
            }
        ],
        'generationConfig': {
            'temperature': 0.2,
            'maxOutputTokens': 300,
        },
    }).encode('utf-8')

    request = Request(
        f'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent',
        data=body,
        headers={
            'Content-Type': 'application/json',
            'x-goog-api-key': selected_key,
        },
        method='POST',
    )

    try:
        with urlopen(request, timeout=90) as response:
            payload = json.loads(response.read().decode('utf-8'))
    except HTTPError as error:
        raise LocalAIError(_gemini_error_message(error)) from error
    except URLError as error:
        raise LocalAIError(_gemini_error_message(error)) from error
    except json.JSONDecodeError as error:
        raise LocalAIError('Gemini devolvió una respuesta JSON no válida.') from error
    except OSError as error:
        raise LocalAIError(f'Gemini falló por un error del sistema: {error}') from error

    if not payload:
        raise LocalAIError('Gemini devolvió una respuesta vacía.')

    try:
        summary = payload['candidates'][0]['content']['parts'][0]['text'].strip()
    except (KeyError, IndexError, TypeError):
        raise LocalAIError('Gemini devolvió una respuesta sin candidates o sin contenido válido.')

    if not summary:
        raise LocalAIError('Gemini devolvió un resumen vacío.')

    if _contains_unsupported_claim(summary, result):
        return grounded_summary(result)

    return summary


def generate_summary(
    result: ScanResult,
    model: str = DEFAULT_GEMINI_MODEL,
    api_key: str | None = None,
    endpoint: str | None = None,
    ollama_model: str | None = None,
) -> str:
    """Motor principal de resúmenes: Gemini primero, Ollama como respaldo opcional."""
    selected_key = (api_key or os.getenv('SCANNER_GEMINI_API_KEY') or os.getenv('GEMINI_API_KEY') or '').strip()
    if selected_key:
        return gemini_summary(result=result, model=model, api_key=selected_key)

    try:
        return local_summary(result=result, model=ollama_model, endpoint=endpoint)
    except LocalAIError as error:
        raise LocalAIError(
            'Gemini no está configurado y Ollama no está disponible. Configura SCANNER_GEMINI_API_KEY o GEMINI_API_KEY.'
        ) from error


def gemini_chat(
    question: str,
    result: ScanResult | None = None,
    history: list[tuple[str, str]] | None = None,
    model: str = DEFAULT_GEMINI_MODEL,
    api_key: str | None = None,
) -> str:
    """Responde con el contexto del informe usando Gemini como motor principal."""
    cleaned = question.strip()
    if not cleaned:
        raise LocalAIError('Escribe una pregunta para Karen.')

    selected_key = (api_key or os.getenv('SCANNER_GEMINI_API_KEY') or os.getenv('GEMINI_API_KEY') or '').strip()
    if not selected_key:
        raise LocalAIError('No hay clave de Gemini activa. Configura SCANNER_GEMINI_API_KEY o GEMINI_API_KEY.')

    context = grounded_summary(result) if result else 'No hay un informe cargado todavía.'
    recent = '\n'.join(f'{role}: {text}' for role, text in (history or [])[-6:])
    prompt = (
        'Tu nombre es Karen. Eres la asistente del producto Web Scanner. '
        'Responde en español con tono profesional, directo y claro. '
        'Ayuda a entender observaciones del informe, priorizar revisiones y proponer remediaciones defensivas verificables. '
        'No inventes hallazgos ni recomendaciones sin evidencia. '
        'Mantén la respuesta bajo 180 palabras.\n\n'
        f'CONTEXTO VERIFICADO DEL INFORME:\n{context}\n\n'
        f'CONVERSACIÓN RECIENTE:\n{recent or "(ninguna)"}\n\n'
        f'PREGUNTA DEL USUARIO:\n{cleaned}'
    )

    body = json.dumps({
        'contents': [{'parts': [{'text': prompt}]}],
        'generationConfig': {'temperature': 0.25, 'maxOutputTokens': 360},
    }).encode('utf-8')

    request = Request(
        f'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent',
        data=body,
        headers={'Content-Type': 'application/json', 'x-goog-api-key': selected_key},
        method='POST',
    )

    try:
        with urlopen(request, timeout=90) as response:
            payload = json.loads(response.read().decode('utf-8'))
    except HTTPError as error:
        raise LocalAIError(_gemini_error_message(error)) from error
    except URLError as error:
        raise LocalAIError(_gemini_error_message(error)) from error
    except json.JSONDecodeError as error:
        raise LocalAIError('Gemini devolvió una respuesta JSON no válida.') from error
    except OSError as error:
        raise LocalAIError(f'Gemini falló por un error del sistema: {error}') from error

    if not payload:
        raise LocalAIError('Gemini devolvió una respuesta vacía.')

    try:
        answer = payload['candidates'][0]['content']['parts'][0]['text'].strip()
    except (KeyError, IndexError, TypeError):
        raise LocalAIError('Gemini devolvió una respuesta sin candidates o sin contenido válido.')

    if not answer:
        raise LocalAIError('Gemini devolvió una respuesta vacía.')

    return answer


def gemini_sumary(
    result: ScanResult,
    model: str = DEFAULT_GEMINI_MODEL,
    api_key: str | None = None,
) -> str:
    """Alias para mantener compatibilidad con el nombre anterior."""
    return gemini_summary(result=result, model=model, api_key=api_key)


def karen_reply(
    question: str,
    result: ScanResult | None = None,
    history: list[tuple[str, str]] | None = None,
    model: str | None = None,
    endpoint: str | None = None,
    api_key: str | None = None,
    ollama_model: str | None = None,
) -> str:
    """Chat principal: Gemini primero, Ollama solo como respaldo opcional."""
    selected_key = (api_key or os.getenv('SCANNER_GEMINI_API_KEY') or os.getenv('GEMINI_API_KEY') or '').strip()
    if selected_key:
        return gemini_chat(question, result=result, history=history, model=model or DEFAULT_GEMINI_MODEL, api_key=selected_key)

    try:
        return _legacy_karen_reply(question=question, result=result, history=history, model=ollama_model, endpoint=endpoint)
    except LocalAIError:
        raise LocalAIError(
            'No hay clave de Gemini activa y Ollama no está disponible. Configura SCANNER_GEMINI_API_KEY o GEMINI_API_KEY e intenta de nuevo.'
        )


def _legacy_karen_reply(
    question: str,
    result: ScanResult | None = None,
    history: list[tuple[str, str]] | None = None,
    model: str | None = None,
    endpoint: str | None = None,
) -> str:
    """Compatibilidad para los flujos antiguos de Ollama."""
    cleaned = question.strip()
    if not cleaned:
        raise LocalAIError('Escribe una pregunta para Karen.')
    base_url = (endpoint or os.getenv('SCANNER_OLLAMA_ENDPOINT') or DEFAULT_ENDPOINT).rstrip('/')
    selected_model = model or os.getenv('SCANNER_OLLAMA_MODEL') or DEFAULT_MODEL
    status = ollama_status(base_url)
    if not status.available:
        raise LocalAIError(status.message)
    if selected_model not in status.models:
        raise LocalAIError(f'El modelo {selected_model!r} no está instalado. Ejecuta: ollama pull {selected_model}')
    context = grounded_summary(result) if result else 'No hay un informe cargado todavía.'
    recent = '\n'.join(f'{role}: {text}' for role, text in (history or [])[-6:])
    prompt = (
        'Tu nombre es Karen. Eres la asistente local del producto Web Scanner. '
        'Responde en español e ingles y frances, con tono profesional, directo y claro. '
        'Ayudas a entender observaciones del informe, priorizar revisiones y proponer remediaciones defensivas de alto nivel. '
        'No inventes hallazgos y declara cuando el informe no tiene evidencia suficiente. '
        'No hagas recomendaciones de seguridad que no estén respaldadas por la evidencia del informe. '
        'Mantén la respuesta bajo 180 palabras.\n\n'
        f'CONTEXTO VERIFICADO DEL INFORME:\n{context}\n\n'
        f'CONVERSACIÓN RECIENTE:\n{recent or "(ninguna)"}\n\n'
        f'PREGUNTA DEL USUARIO:\n{cleaned}'
    )
    body = json.dumps({
        'model': selected_model, 'prompt': prompt, 'stream': False,
        'options': {'temperature': 0.25, 'num_predict': 360},
    }).encode('utf-8')
    request = Request(f'{base_url}/api/generate', data=body, headers={'Content-Type': 'application/json'}, method='POST')
    try:
        with urlopen(request, timeout=90) as response:
            answer = str(json.loads(response.read().decode('utf-8')).get('response', '')).strip()
    except (OSError, URLError, json.JSONDecodeError) as error:
        raise LocalAIError('Karen no pudo responder desde Ollama local.') from error
    if not answer:
        raise LocalAIError('Karen devolvió una respuesta vacía.')
    return answer

def gemini_models(api_key: str | None = None) -> tuple[str, ...]:
    """Devuelve la lista de modelos Gemini disponibles para la clave proporcionada."""

    selected_key = (
        api_key
        or os.getenv('SCANNER_GEMINI_API_KEY')
        or os.getenv('GEMINI_API_KEY')
        or ''
    ).strip()

    if not selected_key:
        raise LocalAIError(
            'No hay clave de Gemini activa. '
            'Configura SCANNER_GEMINI_API_KEY o GEMINI_API_KEY.'
        )

    request = Request(
        'https://generativelanguage.googleapis.com/v1beta/models',
        headers={
            'Content-Type': 'application/json',
            'x-goog-api-key': selected_key,
        },
        method='GET',
    )

    try:
        with urlopen(request, timeout=10) as response:
            payload = json.loads(
                response.read().decode('utf-8')
            )

    except HTTPError as error:
        details = error.read().decode('utf-8', errors='replace')
        raise LocalAIError(
            f'Gemini respondió HTTP {error.code}: {details}'
        ) from error

    except (OSError, URLError, json.JSONDecodeError) as error:
        raise LocalAIError(
            f'Gemini no pudo recuperar la lista de modelos: {error}'
        ) from error

    return tuple(
        item.get('name', '')
        for item in payload.get('models', [])
        if item.get('name')
    )
