# Web Scanner

Aplicación de escritorio y CLI para auditorías web defensivas, autorizadas y
de bajo impacto. Analiza DNS, HTTP, cabeceras de seguridad y TLS; conserva un
historial local y exporta resultados JSON o PDF. La interfaz Qt/C++ usa el
motor Python local mediante un protocolo JSON, sin duplicar la lógica de
análisis.

> Úsalo solo en sistemas propios o con autorización explícita del titular.
> Consulta los [términos de uso](TERMS.md) antes de utilizarlo.

## Características

- Módulos defensivos: DNS, HTTP, headers y TLS.
- Hallazgos con evidencia, confianza, estado y recomendación.
- Interfaz nativa Qt con temas, idiomas, historial y exportación.
- JSON siempre disponible; PDF opcional; resumen IA opcional y acotado a la
  evidencia disponible.

## Instalación rápida

Requiere Python 3.10 o posterior y `pip`. Desde la carpeta del repositorio:

```text
python -m venv .venv
```

Activa el entorno y instala la aplicación:

| Sistema | Activar entorno |
| --- | --- |
| Windows PowerShell | `.\.venv\Scripts\Activate.ps1` |
| Windows CMD | `.venv\Scripts\activate.bat` |
| Linux / macOS | `source .venv/bin/activate` |

```text
python -m pip install --upgrade pip
python -m pip install -e .
```

Para habilitar PDF y herramientas de prueba:

```text
python -m pip install -e ".[reports,dev]"
```

Si PowerShell bloquea la activación del entorno, ejecuta una vez en la sesión:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## Uso

```text
web-scanner --gui
web-scanner https://example.com
web-scanner https://example.com --modules dns http headers tls --output resultado.json
web-scanner https://example.com --pdf informe.pdf
```

También puedes ejecutar `python -m scanner --help` cuando el paquete esté
instalado. Consulta la [guía de usuario](GUIA_USUARIO.md) para los flujos de
interfaz, CLI, informes e IA.

## Interfaz nativa C++ (opcional)

La aplicación Python funciona en Windows, Linux y macOS mediante PySide6. La
interfaz nativa alternativa requiere Qt 6.6+, CMake 3.24+ y un compilador C++:

```text
cmake -S cpp -B cpp/build -DCMAKE_PREFIX_PATH="RUTA_A_QT"
cmake --build cpp/build --config Release
```

En Windows usa un kit Qt/MSVC compatible. En Linux instala el compilador y las
bibliotecas de desarrollo Qt6. En macOS instala Xcode Command Line Tools y Qt6.
Ejecuta el binario generado desde `cpp/build` y define `WEB_SCANNER_PYTHON` si
necesitas indicar un intérprete Python concreto.

## Desarrollo y publicación

```text
python -m pytest -q
cmake -S cpp -B cpp/build -DWEB_SCANNER_BUILD_TESTS=ON -DBUILD_TESTING=ON
cmake --build cpp/build --config Release
ctest --test-dir cpp/build -C Release --output-on-failure
```

Antes de publicar, revisa que no subes `.venv`, `.scanner`, PDFs, JSON privados,
tokens, cookies ni archivos `.env`. La [licencia](LICENSE) exige atribución a
Web Scanner y prohíbe cobrar por distribuir esta versión sin permiso escrito.
La anterior versión Apache-2.0 conserva sus derechos históricos; esta
restricción no puede revocarlos.
