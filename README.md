# Web Scanner

Herramienta CLI de reconocimiento y auditoría web defensiva para pentesters,
administradores y equipos de seguridad que realizan pruebas autorizadas.

Web Scanner ayuda a analizar la superficie pública de una aplicación web,
interpretar sus registros DNS, revisar TLS y headers de seguridad, identificar
tecnologías y detectar señales de CDN o WAF sin confundir la infraestructura de
Cloudflare con la IP de origen del servidor.

El proyecto prioriza la precisión sobre la agresividad: diferencia entre
información observada, configuración potencialmente insegura y vulnerabilidad
no confirmada. Los resultados incluyen evidencia, severidad, confianza y
recomendaciones para facilitar una revisión manual.

Está pensado como una base abierta para aprender, mejorar y colaborar en
herramientas de seguridad web responsables.

> Uso exclusivo en sistemas propios o con autorización explícita.

## Web Scanner

El archivo `web_scanner.py` implementa el analizador principal del proyecto.

### Características

- Resolución DNS de registros A, AAAA, MX, NS y TXT.
- Detección de Cloudflare como CDN/proxy mediante DNS e indicadores HTTP.
- Búsqueda pasiva de posibles referencias históricas y subdominios.
- Enumeración opcional mediante wordlist local, incluida la de SecLists/Kali.
- Detección de tecnologías basada en firmas regex.
- Análisis de headers de seguridad modernos.
- Análisis TLS con separación entre protocolo negociado y sondas no concluyentes.
- Detección de WAF sin asumir que Cloudflare implica un WAF confirmado.
- Descubrimiento de contenido, backups, APIs, Git expuesto y JWT.
- Escaneo TCP común opcional.
- Hallazgos con severidad, confianza, estado, evidencia y recomendación.
- Exportación de resultados a JSON.

### Instalación en Linux

```bash
sudo apt update
sudo apt install python3 python3-venv

python3 -m venv .venv-scanner
source .venv-scanner/bin/activate
python -m pip install --upgrade pip
python -m pip install requests dnspython beautifulsoup4
```

### Uso

Análisis completo de bajo impacto:

```bash
python3 web_scanner.py --all https://example.com
```

Con timeout y salida JSON:

```bash
python3 web_scanner.py --all https://example.com \
  --timeout 5 \
  --output resultado.json
```

Usando un diccionario local de subdominios:

```bash
python3 web_scanner.py https://example.com \
  --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --workers 40
```

Módulos opcionales explícitos:

```bash
python3 web_scanner.py https://example.com --ssl --waf --content
python3 web_scanner.py https://example.com --scan-ports --port-timeout 1
python3 web_scanner.py https://example.com --xss --sql
```

### Interpretación de Cloudflare

Una IP dentro de los rangos de Cloudflare se muestra como `Observed Cloudflare
edge IP` o `Cloudflare proxy IP`. Eso no representa necesariamente la IP de
origen. Si no existe evidencia pública suficiente, el resultado correcto es:

```text
IP real: No descubierta
WAF: No confirmado
```

La herramienta no intenta evadir Cloudflare ni confirmar vulnerabilidades con
una sola señal. Los resultados potenciales se etiquetan como no confirmados y
los headers ausentes se reportan como observaciones de severidad baja.

### Contribuir

Este proyecto está abierto a mejoras, ideas y revisiones de la comunidad.
Si tienes experiencia en Python, redes, DNS, TLS, testing web o reporting,
puedes ayudar de varias formas:

- Abrir un **Issue** para informar un bug o proponer una mejora.
- Compartir ejemplos de falsos positivos o resultados no concluyentes.
- Proponer mejoras de documentación, tests, rendimiento o compatibilidad.
- Crear un **Pull Request** con una implementación pequeña y explicada.
- Publicar tu propia versión derivada respetando la licencia del proyecto.

Para contribuir mediante Pull Request:

```bash
git clone https://github.com/TU_USUARIO/TU_REPOSITORIO.git
cd TU_REPOSITORIO
git checkout -b mejora/nombre-de-la-mejora

# Realiza cambios y prueba el programa
python3 -m py_compile web_scanner.py
python3 web_scanner.py --all https://example.com --timeout 5

git add web_scanner.py README.md
git commit -m "Mejora la precision del analisis"
git push -u origin mejora/nombre-de-la-mejora
```

Después abre un Pull Request desde GitHub. Las contribuciones deben mantener
el enfoque defensivo y autorizado del proyecto, evitar secretos en el código,
no introducir técnicas de evasión y explicar qué cambió y cómo se probó.

Las ideas especialmente útiles incluyen pruebas automatizadas, reducción de
falsos positivos, soporte para más plataformas, mejores firmas tecnológicas,
análisis TLS más preciso y reportes más claros.

### Comunidad

No hay garantía de que un repositorio nuevo reciba atención inmediata, pero un
proyecto público, con documentación clara, ejemplos reproducibles y issues
bien descritos tiene muchas más posibilidades de ser descubierto y recibir
feedback. Comparte el enlace en comunidades de Python, seguridad defensiva y
CTF, siempre presentándolo como una herramienta para auditorías autorizadas.

### Publicar en GitHub

Instala Git y configura tu identidad una sola vez:

```bash
git config --global user.name "Tu Nombre"
git config --global user.email "tu-correo@example.com"
```

Desde la carpeta del proyecto:

```bash
git init
git add README.md web_scanner.py .gitignore
git commit -m "Publica auditor de seguridad web defensivo"
git branch -M main
git remote add origin https://github.com/TU_USUARIO/TU_REPOSITORIO.git
git push -u origin main
```

Antes de publicar, comprueba que no incluyes `.venv/`, `__pycache__/`, logs,
tokens, contraseñas, cookies, resultados privados ni archivos con datos de
clientes. Crea primero un repositorio vacío en GitHub y sustituye la URL del
comando `git remote add origin` por la de tu repositorio.

