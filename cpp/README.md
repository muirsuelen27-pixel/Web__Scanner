# Native Web Scanner desktop

This directory contains the Qt 6 Widgets presentation layer. It does not
duplicate the scan engine, local history, report rendering, or AI providers:
the C++ application starts `python -m scanner.bridge` with `QProcess` and
exchanges one JSON object per line. The Python process is local, long-lived,
and writes protocol messages only to stdout; diagnostic logs go to stderr.

## Build on Windows

Install Qt 6.6 or newer with the matching MSVC kit, CMake 3.24+, and a Visual
Studio C++ workload. Add Qt's `CMAKE_PREFIX_PATH` when Qt is not discoverable
by CMake:

From the repository root, install the Python package first so the backend can
be found by the native application, then configure CMake:

```powershell
python -m pip install -e .
cmake -S cpp -B cpp\build `
  -DCMAKE_PREFIX_PATH="C:\Qt\6.8.0\msvc2022_64"
cmake --build cpp\build --config Release
```

Run `cpp\build\Release\web_scanner.exe`. The adapter resolves the
project root at configure time and prefers `.venv\Scripts\python.exe`; set
`WEB_SCANNER_PYTHON` if the backend should use another interpreter.

Until the native executable exists, use `web-scanner --gui` for the Python
development fallback. The standalone CLI is unchanged.

## Layout

```text
scanner/cpp/
├── CMakeLists.txt
├── assets/
│   ├── logo.svg
│   └── icons/                 # Local vector icons, embedded into the app
├── cmake/BuildConfig.h.in
├── i18n/                      # Qt Linguist source catalogs
├── include/
│   ├── core/                  # Python process, theme, language services
│   ├── models/                # QAbstractTableModel + filter proxy
│   ├── ui/                    # Main window and four pages
│   └── widgets/               # Sidebar, animated cards/buttons, toast
├── resources/webscanner.qrc
├── src/                       # C++ implementations
├── tests/                     # Optional Qt model tests
└── themes/                    # QSS palettes, accent overlays, chat bubble CSS
```

## Integration and behavior

- The backend request envelope is `{id, operation, ...}` and the response is
  `{id, ok, ...}`. Scan progress is a separate `{event: "progress", id, ...}`
  line. The bridge validates the module allow-list and settings before calling
  the existing Python APIs.
- `QSettings` persists display and scan preferences. Scan reports continue to
  live in the existing `.scanner/history` local store.
- Finding, technology, and history tables are model/view tables. The findings
  proxy filters text, severity, confidence, and module; technology and history
  use their own text-filter proxies.
- `Ctrl+K` focuses global search; `Ctrl+Shift+K` opens Karen. The original
  shortcut request assigned both meanings to `Ctrl+K`, which is ambiguous.
  `Ctrl+R`, `Ctrl+H`, `Ctrl+,`, `Ctrl+E`, and `F5` remain available.
- Locale changes install the selected `.qm` catalog at runtime. The UI ships
  English, Spanish, and French sample catalogs; run the `update-translations`
  CMake target after changing `tr()` strings.
- Dark/light base QSS is combined with cyan/indigo/emerald accent overlays.
  Auto mode follows Qt's system color-scheme hint. The bundled SVG artwork is
  original project artwork; system UI fonts are used to avoid a font license
  and distribution burden.
- The GUI has no QML dependency. Qt SVG support is used to render bundled SVG
  assets. Toasts are non-blocking; confirmation dialogs remain modal for
  destructive history operations.

## Tests

```powershell
python -m pip install -e ".[dev]"
python -m pytest -q
cmake -S cpp -B cpp\build -DWEB_SCANNER_BUILD_TESTS=ON `
  -DBUILD_TESTING=ON -DCMAKE_PREFIX_PATH="C:\Qt\6.8.0\msvc2022_64"
cmake --build cpp\build --config Release
ctest --test-dir cpp\build -C Release --output-on-failure
```
