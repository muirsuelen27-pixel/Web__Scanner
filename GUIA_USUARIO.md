# Guía rápida de usuario

## Antes de analizar

1. Confirma que eres propietario del sitio o tienes autorización escrita.
2. Empieza con el perfil estándar y un objetivo HTTPS concreto.
3. Lee la evidencia de cada resultado; una configuración ausente no confirma
   por sí sola una vulnerabilidad.

## Interfaz gráfica

Ejecuta `web-scanner --gui`. Escribe una URL, elige los módulos DNS, HTTP,
headers y/o TLS, y pulsa **Iniciar análisis**. Al terminar puedes consultar el
detalle, guardar JSON o PDF, y revisar el historial local.

## Línea de comandos

```powershell
web-scanner https://example.com --modules dns http headers tls
web-scanner https://example.com --output resultado.json
web-scanner https://example.com --pdf informe.pdf
```

El PDF requiere instalar el extra `reports`. La opción `--ai-summary` requiere
una clave `SCANNER_GEMINI_API_KEY`/`GEMINI_API_KEY`, o bien Ollama local con el
modelo solicitado. Nunca pegues claves en el código ni las subas a GitHub.

## Interpretar resultados

- **Observed**: dato detectado; no significa una falla por sí mismo.
- **Missing**: configuración esperada no encontrada; requiere revisión.
- **Confidence**: estima la calidad de la evidencia, no la gravedad real del
  negocio.
- **Errores del módulo**: indican que la comprobación no fue concluyente.
