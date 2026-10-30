"""Aplicación de escritorio local-first para auditorías defensivas."""

from __future__ import annotations

import sys
from html import escape
from pathlib import Path

from .config import ScannerConfig, normalize_target
from .engine import DefensiveScanner
from .models import Finding, ScanResult
from .reporting import export_json, export_pdf
from .storage import AppSettings, LocalStore


def launch(target: str = '', output: str | None = None) -> int:
    """Abre el panel sin duplicar la lógica de análisis o de reportes."""
    try:
        from PySide6.QtCore import QEasingCurve, QObject, QPropertyAnimation, QThread, Signal, Qt
        from PySide6.QtGui import QColor, QFont, QIcon
        from PySide6.QtSvgWidgets import QSvgWidget
        from PySide6.QtWidgets import (
            QApplication, QCheckBox, QComboBox, QDoubleSpinBox, QFileDialog, QFrame,
            QGridLayout, QHBoxLayout, QHeaderView, QLabel,
            QLineEdit, QMainWindow, QMessageBox, QPushButton, QProgressBar,
            QSpinBox, QSplitter, QStackedWidget, QTableWidget, QTableWidgetItem,
            QTabWidget, QTextBrowser, QVBoxLayout, QWidget,
        )
    except ImportError as error:
        raise RuntimeError('Instala PySide6 para usar --gui') from error

    # The native Qt asset is also used by the Python development fallback.
    # Keeping one source of truth prevents the fallback from depending on an
    # asset folder that is not part of this distribution.
    logo_path = Path(__file__).parent / 'cpp' / 'assets' / 'logo.svg'
    project_root = Path(__file__).parent.parent

    class ScanWorker(QObject):
        progress = Signal(str, int, int)
        completed = Signal(object)
        failed = Signal(str)

        def __init__(self, config: ScannerConfig, modules: tuple[str, ...]) -> None:
            super().__init__()
            self.config = config
            self.modules = modules

        def run(self) -> None:
            try:
                result = DefensiveScanner(self.config, self.progress.emit).run(self.modules)
            except Exception as error:
                self.failed.emit(str(error))
                return
            self.completed.emit(result)

    class KarenWorker(QObject):
        completed = Signal(str)
        failed = Signal(str)

        def __init__(self, question: str, result: ScanResult | None, history: list[tuple[str, str]], ollama_model: str) -> None:
            super().__init__()
            self.question = question
            self.result = result
            self.history = history
            self.ollama_model = ollama_model

        def run(self) -> None:
            try:
                from .ai import karen_reply
                self.completed.emit(karen_reply(
                    self.question,
                    self.result,
                    self.history,
                    ollama_model=self.ollama_model,
                ))
            except Exception as error:
                self.failed.emit(str(error))

    class MetricCard(QFrame):
        def __init__(self, label: str, color: str) -> None:
            super().__init__()
            self.setObjectName('metricCard')
            self.caption = QLabel(label.upper())
            self.value = QLabel('—')
            self.value.setObjectName('metricValue')
            self.value.setStyleSheet(f'color: {color};')
            layout = QVBoxLayout(self)
            layout.setContentsMargins(16, 13, 16, 13)
            layout.addWidget(self.caption)
            layout.addWidget(self.value)

        def set_value(self, value: object) -> None:
            self.value.setText(str(value))

    class ScannerWindow(QMainWindow):
        accents = {
            'cyan': ('#0891B2', '#22D3EE', '#7DD3FC'),
            'indigo': ('#4F46E5', '#818CF8', '#C7D2FE'),
            'emerald': ('#059669', '#34D399', '#A7F3D0'),
        }

        def __init__(self) -> None:
            super().__init__()
            self.store = LocalStore(project_root / '.scanner')
            self.settings = self.store.load_settings()
            self.result: ScanResult | None = None
            self.ai_summary: str | None = None
            self.history_path: Path | None = None
            self.history_records: list[tuple[Path, ScanResult, str | None]] = []
            self.thread: QThread | None = None
            self.worker: ScanWorker | None = None
            self.chat_thread: QThread | None = None
            self.chat_worker: KarenWorker | None = None
            self.setWindowTitle('Web Scanner')
            self.setWindowIcon(QIcon(str(logo_path)))
            self.resize(1440, 900)
            self.setMinimumSize(1120, 720)
            self._build_ui()
            self._load_settings_controls()
            self._apply_theme()
            self.target_input.setText(target)
            self.refresh_history()

        def _build_ui(self) -> None:
            root = QWidget()
            shell = QHBoxLayout(root)
            shell.setContentsMargins(0, 0, 0, 0)
            shell.setSpacing(0)
            shell.addWidget(self._build_sidebar())
            content = QWidget()
            layout = QVBoxLayout(content)
            layout.setContentsMargins(38, 32, 38, 32)
            layout.setSpacing(20)
            layout.addLayout(self._build_header())
            self.stack = QStackedWidget()
            self.analysis_page = self._build_analysis_page()
            self.history_page = self._build_history_page()
            self.chat_page = self._build_chat_page()
            self.settings_page = self._build_settings_page()
            self.stack.addWidget(self.analysis_page)
            self.stack.addWidget(self.history_page)
            self.stack.addWidget(self.chat_page)
            self.stack.addWidget(self.settings_page)
            layout.addWidget(self.stack, 1)
            shell.addWidget(content, 1)
            self.setCentralWidget(root)

        def _build_sidebar(self) -> QFrame:
            sidebar = QFrame()
            sidebar.setObjectName('sidebar')
            sidebar.setFixedWidth(262)
            layout = QVBoxLayout(sidebar)
            layout.setContentsMargins(25, 29, 25, 25)
            mark = QSvgWidget(str(logo_path))
            mark.setFixedSize(64, 64)
            layout.addWidget(mark)
            brand = QLabel('WEB SCANNER')
            brand.setObjectName('brand')
            layout.addWidget(brand)
            subtitle = QLabel('SECURITY INTELLIGENCE')
            subtitle.setObjectName('sidebarCaption')
            layout.addWidget(subtitle)
            layout.addSpacing(36)
            self.nav_buttons: list[QPushButton] = []
            for index, label in enumerate(('◈  Nuevo análisis', '◷  Historial y reportes', '✦  Karen', '⚙  Configuración')):
                button = QPushButton(label)
                button.setObjectName('navButton')
                button.setCheckable(True)
                button.clicked.connect(lambda checked, page=index: self.show_page(page))
                self.nav_buttons.append(button)
                layout.addWidget(button)
            self.nav_buttons[0].setChecked(True)
            layout.addStretch(1)
            return sidebar

        def _build_header(self) -> QHBoxLayout:
            layout = QHBoxLayout()
            text = QVBoxLayout()
            self.page_title = QLabel('Centro de análisis')
            self.page_title.setObjectName('pageTitle')
            self.page_subtitle = QLabel('Evidencia clara. Resultados reproducibles.')
            text.addWidget(self.page_title)
            text.addWidget(self.page_subtitle)
            layout.addLayout(text)
            layout.addStretch(1)
            return layout

        def _build_analysis_page(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(16)
            layout.addWidget(self._build_target_card())
            layout.addLayout(self._build_metrics())
            layout.addWidget(self._build_results(), 1)
            return page

        def _build_target_card(self) -> QFrame:
            card = QFrame()
            card.setObjectName('targetCard')
            layout = QVBoxLayout(card)
            layout.setContentsMargins(21, 18, 21, 18)
            layout.addWidget(self._label('Objetivo de análisis', 'cardHeading'))
            controls = QHBoxLayout()
            self.target_input = QLineEdit()
            self.target_input.setPlaceholderText('https://example.com')
            self.target_input.returnPressed.connect(self.start_scan)
            self.start_button = QPushButton('Iniciar análisis')
            self.start_button.setObjectName('primaryButton')
            self.start_button.clicked.connect(self.start_scan)
            controls.addWidget(self.target_input, 1)
            controls.addWidget(self.start_button)
            layout.addLayout(controls)
            modules = QHBoxLayout()
            self.module_checks: dict[str, QCheckBox] = {}
            for key, label in (('dns', 'DNS y dominio'), ('http', 'HTTP'), ('headers', 'Headers'), ('tls', 'TLS')):
                check = QCheckBox(label)
                check.setChecked(True)
                self.module_checks[key] = check
                modules.addWidget(check)
            modules.addStretch(1)
            layout.addLayout(modules)
            self.progress_label = QLabel('Perfil estándar: DNS, HTTP, headers y TLS.')
            self.progress_label.setObjectName('progressLabel')
            layout.addWidget(self.progress_label)
            self.progress = QProgressBar()
            self.progress.setRange(0, 100)
            layout.addWidget(self.progress)
            return card

        def _build_metrics(self) -> QGridLayout:
            grid = QGridLayout()
            grid.setSpacing(12)
            self.metrics = {
                'risk': MetricCard('Riesgo observado', '#FBBF24'),
                'findings': MetricCard('Hallazgos', '#38BDF8'),
                'headers': MetricCard('Headers presentes', '#34D399'),
                'duration': MetricCard('Tiempo de respuesta', '#A78BFA'),
            }
            for column, card in enumerate(self.metrics.values()):
                grid.addWidget(card, 0, column)
            return grid

        def _build_results(self) -> QSplitter:
            splitter = QSplitter(Qt.Orientation.Horizontal)
            left = QFrame()
            left_layout = QVBoxLayout(left)
            left_layout.setContentsMargins(0, 0, 0, 0)
            left_layout.addWidget(self._label('Resultados del análisis', 'cardHeading'))
            self.table = self._new_table(['Severidad', 'Hallazgo', 'Confianza', 'Estado'])
            self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            self.table.itemSelectionChanged.connect(self.show_finding_detail)
            self.technology_table = self._new_table(['Tecnología', 'Categoría', 'Evidencia', 'Confianza'])
            self.technology_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
            self.results_tabs = QTabWidget()
            self.results_tabs.addTab(self.table, 'Hallazgos')
            self.results_tabs.addTab(self.technology_table, 'Tecnologías')
            left_layout.addWidget(self.results_tabs, 1)
            buttons = QHBoxLayout()
            self.json_button = QPushButton('Exportar JSON')
            self.pdf_button = QPushButton('Exportar PDF')
            self.ai_button = QPushButton('Resumen con IA')
            for button in (self.json_button, self.pdf_button, self.ai_button):
                button.setEnabled(False)
                buttons.addWidget(button)
            buttons.addStretch(1)
            self.json_button.clicked.connect(self.export_json_result)
            self.pdf_button.clicked.connect(self.export_pdf_result)
            self.ai_button.clicked.connect(self.generate_ai_summary)
            left_layout.addLayout(buttons)
            splitter.addWidget(left)
            detail = QFrame()
            detail_layout = QVBoxLayout(detail)
            detail_layout.setContentsMargins(18, 0, 0, 0)
            detail_layout.addWidget(self._label('Detalle de evidencia', 'cardHeading'))
            self.detail = QTextBrowser()
            self.detail.setHtml('<h3>Sin selección</h3><p>Selecciona un hallazgo para ver evidencia, impacto y recomendación.</p>')
            detail_layout.addWidget(self.detail, 1)
            splitter.addWidget(detail)
            splitter.setSizes([760, 340])
            return splitter

        def _build_history_page(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(self._label('Historial de análisis', 'cardHeading'))
            layout.addWidget(QLabel('Tus informes quedan disponibles para consultar, exportar o eliminar cuando quieras.'))
            split = QSplitter(Qt.Orientation.Horizontal)
            left = QFrame()
            left_layout = QVBoxLayout(left)
            left_layout.setContentsMargins(0, 8, 0, 0)
            self.history_table = self._new_table(['Fecha', 'Objetivo', 'Riesgo', 'Hallazgos'])
            self.history_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            self.history_table.itemSelectionChanged.connect(self.show_history_detail)
            left_layout.addWidget(self.history_table, 1)
            actions = QHBoxLayout()
            reload_button = QPushButton('Actualizar')
            load_button = QPushButton('Abrir en análisis')
            history_json = QPushButton('Exportar JSON')
            history_pdf = QPushButton('Generar PDF')
            delete_button = QPushButton('Borrar seleccionado')
            clear_button = QPushButton('Borrar todo')
            reload_button.clicked.connect(self.refresh_history)
            load_button.clicked.connect(self.open_history_record)
            history_json.clicked.connect(self.export_selected_history_json)
            history_pdf.clicked.connect(self.export_selected_history_pdf)
            delete_button.clicked.connect(self.delete_selected_history)
            clear_button.clicked.connect(self.clear_history)
            for button in (reload_button, load_button, history_json, history_pdf, delete_button, clear_button):
                actions.addWidget(button)
            actions.addStretch(1)
            left_layout.addLayout(actions)
            split.addWidget(left)
            right = QFrame()
            right_layout = QVBoxLayout(right)
            right_layout.setContentsMargins(18, 8, 0, 0)
            right_layout.addWidget(self._label('Informe guardado', 'cardHeading'))
            self.history_detail = QTextBrowser()
            self.history_detail.setHtml('<h3>Sin historial</h3><p>Al finalizar un análisis aparecerá aquí.</p>')
            right_layout.addWidget(self.history_detail, 1)
            split.addWidget(right)
            split.setSizes([760, 340])
            layout.addWidget(split, 1)
            return page

        def _build_chat_page(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(14)
            title_row = QHBoxLayout()
            title_row.addWidget(self._label('Karen', 'cardHeading'))
            title_row.addStretch(1)
            layout.addLayout(title_row)
            layout.addWidget(QLabel('Tu asistente para interpretar hallazgos, ordenar prioridades y convertir resultados técnicos en acciones claras.'))
            self.chat_view = QTextBrowser()
            self.chat_view.setHtml('<div style="padding:18px;"><h2>Hola, soy Karen.</h2><p>Ejecuta un análisis o abre un informe desde Historial. Después pregúntame qué significa cada resultado y por dónde empezar.</p></div>')
            layout.addWidget(self.chat_view, 1)
            suggestion_row = QHBoxLayout()
            for question in ('¿Cuál es la prioridad?', 'Explica los hallazgos', '¿Qué debo corregir primero?'):
                button = QPushButton(question)
                button.clicked.connect(lambda _checked=False, value=question: self.ask_karen(value))
                suggestion_row.addWidget(button)
            suggestion_row.addStretch(1)
            layout.addLayout(suggestion_row)
            controls = QHBoxLayout()
            self.chat_input = QLineEdit()
            self.chat_input.setPlaceholderText('Pregunta sobre el análisis cargado…')
            self.chat_input.returnPressed.connect(self.ask_karen_from_input)
            self.chat_button = QPushButton('Enviar a Karen')
            self.chat_button.setObjectName('primaryButton')
            self.chat_button.clicked.connect(self.ask_karen_from_input)
            clear_chat = QPushButton('Limpiar chat')
            clear_chat.clicked.connect(self.clear_chat)
            controls.addWidget(self.chat_input, 1)
            controls.addWidget(self.chat_button)
            controls.addWidget(clear_chat)
            layout.addLayout(controls)
            self.chat_messages: list[tuple[str, str]] = []
            return page

        def _build_settings_page(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(self._label('Configuración', 'cardHeading'))
            layout.addWidget(QLabel('Personaliza la experiencia y ajusta el comportamiento del próximo análisis.'))
            card = QFrame()
            card.setObjectName('settingsCard')
            form = QGridLayout(card)
            form.setContentsMargins(22, 20, 22, 20)
            form.setHorizontalSpacing(22)
            form.setVerticalSpacing(15)
            self.timeout_input = QDoubleSpinBox()
            self.timeout_input.setRange(1, 120)
            self.timeout_input.setSuffix(' s')
            self.rate_input = QDoubleSpinBox()
            self.rate_input.setRange(0, 30)
            self.rate_input.setSingleStep(0.2)
            self.rate_input.setSuffix(' s entre solicitudes')
            self.redirect_input = QSpinBox()
            self.redirect_input.setRange(0, 20)
            self.model_input = QLineEdit()
            self.model_input.setPlaceholderText('qwen2.5:3b')
            self.accent_input = QComboBox()
            self.accent_input.addItems(['cyan', 'indigo', 'emerald'])
            self.auto_ai_input = QCheckBox('Generar un resumen con Karen al finalizar')
            form.addWidget(QLabel('Timeout de red'), 0, 0)
            form.addWidget(self.timeout_input, 0, 1)
            form.addWidget(QLabel('Rate limit'), 1, 0)
            form.addWidget(self.rate_input, 1, 1)
            form.addWidget(QLabel('Máximo de redirecciones'), 2, 0)
            form.addWidget(self.redirect_input, 2, 1)
            form.addWidget(QLabel('Modelo de Karen'), 3, 0)
            form.addWidget(self.model_input, 3, 1)
            form.addWidget(QLabel('Color de acento'), 4, 0)
            form.addWidget(self.accent_input, 4, 1)
            form.addWidget(self.auto_ai_input, 5, 0, 1, 2)
            save_button = QPushButton('Guardar configuración')
            save_button.setObjectName('primaryButton')
            save_button.clicked.connect(self.save_settings)
            form.addWidget(save_button, 6, 0, 1, 2)
            layout.addWidget(card)
            layout.addStretch(1)
            return page

        def _new_table(self, headers: list[str]) -> QTableWidget:
            table = QTableWidget(0, len(headers))
            table.setHorizontalHeaderLabels(headers)
            table.verticalHeader().hide()
            table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            table.setAlternatingRowColors(True)
            return table

        def _label(self, text: str, object_name: str = '') -> QLabel:
            label = QLabel(text)
            if object_name:
                label.setObjectName(object_name)
            return label

        def show_page(self, index: int) -> None:
            self.stack.setCurrentIndex(index)
            for current, button in enumerate(self.nav_buttons):
                button.setChecked(current == index)
            titles = (
                ('Centro de análisis', 'Evidencia clara. Resultados reproducibles.'),
                ('Historial y reportes', 'Tus informes guardados y listos para exportar.'),
                ('Karen', 'Pregunta, interpreta y organiza las prioridades de tu informe.'),
                ('Configuración', 'Ajusta el comportamiento sin editar código.'),
            )
            self.page_title.setText(titles[index][0])
            self.page_subtitle.setText(titles[index][1])

        def _load_settings_controls(self) -> None:
            self.timeout_input.setValue(self.settings.timeout)
            self.rate_input.setValue(self.settings.rate_limit)
            self.redirect_input.setValue(self.settings.max_redirects)
            self.model_input.setText(self.settings.ollama_model)
            self.accent_input.setCurrentText(self.settings.accent)
            self.auto_ai_input.setChecked(self.settings.auto_ai_summary)

        def save_settings(self) -> None:
            try:
                self.settings = AppSettings(
                    timeout=self.timeout_input.value(), rate_limit=self.rate_input.value(),
                    max_redirects=self.redirect_input.value(), ollama_model=self.model_input.text().strip() or 'qwen2.5:3b',
                    accent=self.accent_input.currentText(), auto_ai_summary=self.auto_ai_input.isChecked(),
                )
                self.store.save_settings(self.settings)
            except ValueError as error:
                QMessageBox.warning(self, 'Configuración no válida', str(error))
                return
            self._apply_theme()
            QMessageBox.information(self, 'Configuración guardada', 'Los ajustes se aplicarán al próximo análisis.')

        def _apply_theme(self) -> None:
            primary, highlight, pale = self.accents[self.settings.accent]
            self.setStyleSheet(f'''
                QMainWindow {{ background: #0B1120; color: #E5EDF6; font-family: "Segoe UI"; }}
                #sidebar {{ background: #0F172A; border-right: 1px solid #263750; }}
                #brand {{ font-size: 23px; font-weight: 800; letter-spacing: 1.5px; color: #F8FBFF; margin-top: 7px; }}
                #sidebarCaption {{ font-size: 10px; font-weight: 700; color: {highlight}; letter-spacing: 1.4px; }}
                #navButton {{ text-align: left; background: transparent; color: #A5B6CC; padding: 14px 15px; border: 1px solid transparent; border-radius: 10px; margin: 3px 0; font-size: 14px; }}
                #navButton:hover {{ background: #17283E; color: #F4FAFF; }}
                #navButton:checked {{ background: {primary}; color: #FFFFFF; font-weight: 800; }}
                #pageTitle {{ font-size: 31px; font-weight: 800; color: #F8FBFF; letter-spacing: .3px; }}
                #targetCard, #metricCard, #settingsCard {{ background: #111C2E; border: 1px solid #2A3E59; border-radius: 14px; }}
                #targetCard:hover, #metricCard:hover {{ border-color: #3E5B7C; background: #142238; }}
                #cardHeading {{ font-size: 17px; font-weight: 750; color: #F7FBFF; }}
                QLabel {{ font-size: 14px; color: #B9C8DA; }}
                QLineEdit, QDoubleSpinBox, QSpinBox, QComboBox {{ background: #0A1527; border: 1px solid #35506F; border-radius: 10px; padding: 11px 13px; color: #F6FAFF; font-size: 15px; min-height: 22px; selection-background-color: {primary}; }}
                QLineEdit:focus, QDoubleSpinBox:focus, QSpinBox:focus, QComboBox:focus {{ background: #0D1A30; border: 1px solid {highlight}; }}
                QPushButton {{ background: #203957; color: #F6FAFF; padding: 12px 17px; border: 1px solid #41617F; border-radius: 10px; font-weight: 700; font-size: 14px; }}
                QPushButton:hover {{ background: {highlight}; border-color: {pale}; color: #06101C; }}
                QPushButton:pressed {{ background: {primary}; color: white; }}
                QPushButton:disabled {{ background: #334155; border-color: transparent; color: #7F91A8; }}
                #primaryButton {{ background: {primary}; color: #FFFFFF; border-color: {highlight}; font-weight: 800; }}
                #primaryButton:hover {{ background: {pale}; color: #04101C; border-color: #FFFFFF; }}
                QCheckBox {{ color: #D5E2F0; spacing: 9px; padding-top: 7px; font-size: 14px; }}
                QCheckBox::indicator {{ width: 18px; height: 18px; border: 1px solid #557491; border-radius: 6px; background: #0A1527; }}
                QCheckBox::indicator:checked {{ background: {highlight}; border-color: {pale}; }}
                QProgressBar {{ background: #091426; border: 1px solid #263C59; height: 10px; border-radius: 5px; text-align: center; color: transparent; }}
                QProgressBar::chunk {{ background: {highlight}; border-radius: 5px; }}
                #progressLabel {{ color: #AEBFD4; font-size: 13px; padding-top: 3px; }}
                #metricValue {{ font-size: 29px; font-weight: 800; }} #metricCard QLabel:first-child {{ color: #AFC1D6; font-size: 11px; font-weight: 700; letter-spacing: .8px; }}
                QTableWidget, QTextBrowser {{ background: #111C2E; border: 1px solid #2A3E59; border-radius: 12px; color: #EAF3FF; font-size: 14px; }}
                QTableWidget::item {{ padding: 10px; }} QTableWidget::item:selected {{ background: #1E4E70; }} QTableWidget::item:alternate {{ background: #0E192A; }}
                QHeaderView::section {{ background: #1C304A; color: #C9DAEB; border: 0; padding: 11px; font-size: 12px; font-weight: 800; }} QTextBrowser {{ padding: 14px; line-height: 1.45; }}
                QSplitter::handle {{ background: #0B1120; width: 14px; }} QSplitter::handle:hover {{ background: #294966; }}
            ''')

        def start_scan(self) -> None:
            if self.thread and self.thread.isRunning():
                return
            try:
                config = ScannerConfig(
                    normalize_target(self.target_input.text()), timeout=self.settings.timeout,
                    rate_limit=self.settings.rate_limit, max_redirects=self.settings.max_redirects,
                )
            except ValueError as error:
                QMessageBox.warning(self, 'Objetivo no válido', str(error))
                return
            modules = tuple(name for name, check in self.module_checks.items() if check.isChecked())
            if not modules:
                QMessageBox.warning(self, 'Sin módulos', 'Selecciona al menos una comprobación.')
                return
            self._reset_results()
            self.start_button.setEnabled(False)
            self.progress_label.setText('Preparando análisis…')
            self.thread = QThread(self)
            self.worker = ScanWorker(config, modules)
            self.worker.moveToThread(self.thread)
            self.thread.started.connect(self.worker.run)
            self.worker.progress.connect(self.update_progress)
            self.worker.completed.connect(self.scan_completed)
            self.worker.failed.connect(self.scan_failed)
            self.worker.completed.connect(self.thread.quit)
            self.worker.failed.connect(self.thread.quit)
            self.thread.finished.connect(self.worker.deleteLater)
            self.thread.finished.connect(self.thread.deleteLater)
            self.thread.finished.connect(self._release_worker)
            self.thread.start()

        def _release_worker(self) -> None:
            self.worker = None
            self.thread = None

        def update_progress(self, label: str, step: int, total: int) -> None:
            self.progress_label.setText(label + '…')
            self._animate_progress(round(step * 100 / max(total, 1)))

        def scan_completed(self, result: ScanResult) -> None:
            self.result = result
            self.ai_summary = None
            if self.settings.auto_ai_summary:
                self.ai_summary = self._create_ai_summary(show_errors=False)
            self.history_path = self.store.save_result(result, self.ai_summary)
            self.refresh_history()
            self._animate_progress(100)
            self.progress_label.setText('Análisis completado. El informe ya está disponible en Historial.')
            self.start_button.setEnabled(True)
            self._populate_results()
            for button in (self.json_button, self.pdf_button, self.ai_button):
                button.setEnabled(True)

        def scan_failed(self, message: str) -> None:
            self.start_button.setEnabled(True)
            self.progress_label.setText('El análisis no pudo iniciarse.')
            QMessageBox.critical(self, 'Error de análisis', message)

        def _animate_progress(self, end: int) -> None:
            animation = QPropertyAnimation(self.progress, b'value', self)
            animation.setDuration(260)
            animation.setStartValue(self.progress.value())
            animation.setEndValue(end)
            animation.setEasingCurve(QEasingCurve.Type.OutCubic)
            animation.start()
            self._progress_animation = animation

        def _reset_results(self) -> None:
            self.result = None
            self.ai_summary = None
            self.history_path = None
            self.table.setRowCount(0)
            self.technology_table.setRowCount(0)
            self.detail.clear()
            self._animate_progress(0)
            for card in self.metrics.values():
                card.set_value('—')
            for button in (self.json_button, self.pdf_button, self.ai_button):
                button.setEnabled(False)

        def _populate_results(self) -> None:
            if not self.result:
                return
            headers = self.result.metadata.get('security_headers', {})
            http = self.result.metadata.get('http', {})
            self.metrics['risk'].set_value(self.result.risk_level)
            self.metrics['findings'].set_value(len(self.result.findings))
            self.metrics['headers'].set_value(f"{len(headers.get('present', []))}/6" if isinstance(headers, dict) else '—')
            self.metrics['duration'].set_value(f"{http.get('elapsed_ms', '—')} ms" if isinstance(http, dict) else '—')
            self._fill_finding_table(self.table, self.result.findings)
            technologies = self.result.metadata.get('technologies', [])
            self._fill_technology_table(
                self.technology_table,
                technologies if isinstance(technologies, list) else [],
            )
            if self.result.findings:
                self.table.selectRow(0)

        def _fill_finding_table(self, table: QTableWidget, findings: list[Finding]) -> None:
            table.setRowCount(len(findings))
            colors = {'CRITICAL': '#F87171', 'HIGH': '#FB923C', 'MEDIUM': '#FBBF24', 'LOW': '#60A5FA', 'INFO': '#94A3B8'}
            for row, finding in enumerate(findings):
                for column, value in enumerate((finding.severity, finding.title, finding.confidence, finding.status)):
                    item = QTableWidgetItem(value)
                    if column == 0:
                        item.setForeground(QColor(colors[finding.severity]))
                    table.setItem(row, column, item)

        def _fill_technology_table(self, table: QTableWidget, technologies: list[dict]) -> None:
            records = [technology for technology in technologies if isinstance(technology, dict)]
            table.setRowCount(len(records))
            fields = ('name', 'category', 'evidence', 'confidence')
            for row, technology in enumerate(records):
                for column, field in enumerate(fields):
                    table.setItem(row, column, QTableWidgetItem(str(technology.get(field, ''))))

        def show_finding_detail(self) -> None:
            if not self.result:
                return
            row = self.table.currentRow()
            if 0 <= row < len(self.result.findings):
                self.detail.setHtml(self._finding_html(self.result.findings[row]))

        def _finding_html(self, finding: Finding) -> str:
            return (
                f'<h2>{finding.title}</h2><p><b>Severidad:</b> {finding.severity} &nbsp; <b>Confianza:</b> {finding.confidence}</p><hr/>'
                f'<h3>Descripción</h3><p>{finding.description}</p><h3>Evidencia</h3><p>{finding.evidence}</p>'
                f'<h3>Impacto</h3><p>{finding.impact}</p><h3>Recomendación</h3><p>{finding.recommendation}</p>'
            )

        def _create_ai_summary(self, show_errors: bool = True) -> str | None:
            if not self.result:
                return None
            try:
                from .ai import DEFAULT_GEMINI_MODEL, LocalAIError, generate_summary
                return generate_summary(self.result, model=DEFAULT_GEMINI_MODEL)
            except (LocalAIError, OSError) as error:
                if show_errors:
                    QMessageBox.information(self, 'IA no disponible', str(error))
                return None

        def generate_ai_summary(self) -> None:
            summary = self._create_ai_summary()
            if not summary:
                return
            self.ai_summary = summary
            if self.history_path and self.result:
                self.store.update_result(self.history_path, self.result, summary)
                self.refresh_history()
            self.detail.setHtml(f'<h2>Resumen ejecutivo de Karen</h2><p>{escape(summary)}</p>')
            self.progress_label.setText('Resumen listo. El próximo PDF lo incluirá automáticamente.')

        def export_json_result(self) -> None:
            if self.result:
                self._export_json(self.result)

        def export_pdf_result(self) -> None:
            if self.result:
                self._export_pdf(self.result, self.ai_summary)

        def _export_json(self, result: ScanResult) -> None:
            destination, _ = QFileDialog.getSaveFileName(self, 'Guardar resultados JSON', 'web_scanner_result.json', 'JSON (*.json)')
            if destination:
                export_json(result, destination)
                self._saved_message(Path(destination))

        def _export_pdf(self, result: ScanResult, summary: str | None) -> None:
            destination, _ = QFileDialog.getSaveFileName(self, 'Guardar informe PDF', 'web_scanner_report.pdf', 'PDF (*.pdf)')
            if destination:
                export_pdf(result, destination, executive_summary=summary)
                self._saved_message(Path(destination))

        def refresh_history(self) -> None:
            self.history_records = self.store.list_results()
            self.history_table.setRowCount(len(self.history_records))
            for row, (_path, result, _summary) in enumerate(self.history_records):
                values = (result.started_at.replace('T', ' ')[:19], result.target, result.risk_level, str(len(result.findings)))
                for column, value in enumerate(values):
                    self.history_table.setItem(row, column, QTableWidgetItem(value))
            if self.history_records:
                self.history_table.selectRow(0)

        def _selected_history(self) -> tuple[Path, ScanResult, str | None] | None:
            row = self.history_table.currentRow()
            return self.history_records[row] if 0 <= row < len(self.history_records) else None

        def show_history_detail(self) -> None:
            selected = self._selected_history()
            if not selected:
                return
            _path, result, summary = selected
            counts = result.counts()
            html = f'<h2>{result.target}</h2><p><b>Riesgo observado:</b> {result.risk_level}<br/><b>Inicio:</b> {result.started_at}</p>'
            html += '<h3>Distribución</h3><p>' + ' · '.join(f'{key}: {value}' for key, value in counts.items()) + '</p>'
            if summary:
                html += f'<h3>Resumen ejecutivo de Karen</h3><p>{escape(summary)}</p>'
            html += '<h3>Hallazgos</h3>' + ''.join(f'<p><b>[{finding.severity}]</b> {finding.title}</p>' for finding in result.findings)
            self.history_detail.setHtml(html)

        def delete_selected_history(self) -> None:
            selected = self._selected_history()
            if not selected:
                QMessageBox.information(self, 'Sin selección', 'Selecciona un informe del historial primero.')
                return
            path, result, _summary = selected
            answer = QMessageBox.question(
                self, 'Borrar informe',
                f'¿Eliminar el informe de {result.target} del historial?\nEsta acción no se puede deshacer.',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer == QMessageBox.StandardButton.Yes:
                self.store.delete_result(path)
                if self.history_path == path:
                    self.history_path = None
                self.refresh_history()

        def clear_history(self) -> None:
            if not self.history_records:
                return
            answer = QMessageBox.question(
                self, 'Borrar historial',
                f'¿Eliminar los {len(self.history_records)} informes guardados?\nEsta acción no se puede deshacer.',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer == QMessageBox.StandardButton.Yes:
                self.store.clear_history()
                self.history_path = None
                self.refresh_history()
                self.history_detail.setHtml('<h3>Historial eliminado</h3><p>Ejecuta un nuevo análisis para crear un informe.</p>')

        def open_history_record(self) -> None:
            selected = self._selected_history()
            if not selected:
                return
            self.history_path, self.result, self.ai_summary = selected
            self._populate_results()
            for button in (self.json_button, self.pdf_button, self.ai_button):
                button.setEnabled(True)
            self.show_page(0)
            self.progress_label.setText('Informe histórico cargado. No se ejecutó un nuevo análisis.')

        def export_selected_history_json(self) -> None:
            selected = self._selected_history()
            if selected:
                self._export_json(selected[1])

        def export_selected_history_pdf(self) -> None:
            selected = self._selected_history()
            if selected:
                self._export_pdf(selected[1], selected[2])

        def ask_karen_from_input(self) -> None:
            question = self.chat_input.text().strip()
            if question:
                self.chat_input.clear()
                self.ask_karen(question)

        def ask_karen(self, question: str) -> None:
            if self.chat_thread and self.chat_thread.isRunning():
                return
            self.chat_messages.append(('Usuario', question))
            self._render_chat(waiting=True)
            self.chat_button.setEnabled(False)
            self.chat_thread = QThread(self)
            self.chat_worker = KarenWorker(question, self.result, self.chat_messages[:-1], self.settings.ollama_model)
            self.chat_worker.moveToThread(self.chat_thread)
            self.chat_thread.started.connect(self.chat_worker.run)
            self.chat_worker.completed.connect(self.karen_completed)
            self.chat_worker.failed.connect(self.karen_failed)
            self.chat_worker.completed.connect(self.chat_thread.quit)
            self.chat_worker.failed.connect(self.chat_thread.quit)
            self.chat_thread.finished.connect(self.chat_worker.deleteLater)
            self.chat_thread.finished.connect(self.chat_thread.deleteLater)
            self.chat_thread.finished.connect(self._release_karen)
            self.chat_thread.start()

        def karen_completed(self, answer: str) -> None:
            self.chat_messages.append(('Karen', answer))
            self.chat_button.setEnabled(True)
            self._render_chat()

        def karen_failed(self, message: str) -> None:
            self.chat_messages.append(('Karen', f'No pude responder en este momento: {message}'))
            self.chat_button.setEnabled(True)
            self._render_chat()

        def _release_karen(self) -> None:
            self.chat_worker = None
            self.chat_thread = None

        def clear_chat(self) -> None:
            self.chat_messages.clear()
            self.chat_view.setHtml('<div style="padding:18px;"><h2>Hola, soy Karen.</h2><p>La conversación se limpió. Puedo ayudarte con el próximo informe que cargues.</p></div>')

        def _render_chat(self, waiting: bool = False) -> None:
            bubbles: list[str] = []
            for role, text in self.chat_messages:
                color = '#163B52' if role == 'Usuario' else '#18283B'
                heading = '#7DD3FC' if role == 'Usuario' else '#A7F3D0'
                bubbles.append(
                    f'<div style="background:{color}; border:1px solid #31516C; padding:14px 16px; '
                    f'border-radius:15px; margin:11px 3px;">'
                    f'<b style="color:{heading};">{role}</b><br/><span style="line-height:145%;">{escape(text).replace(chr(10), "<br/>")}</span></div>'
                )
            if waiting:
                bubbles.append('<p style="color:#AFC4D9; margin:14px;">✦ Karen está preparando una respuesta…</p>')
            self.chat_view.setHtml(''.join(bubbles) or '<p style="padding:18px;">Escribe una pregunta para comenzar.</p>')
            self.chat_view.verticalScrollBar().setValue(self.chat_view.verticalScrollBar().maximum())

        def _saved_message(self, path: Path) -> None:
            QMessageBox.information(self, 'Informe guardado', f'Se guardó correctamente en:\n{path}')

    app = QApplication.instance() or QApplication(sys.argv)
    app.setFont(QFont('Segoe UI', 10))
    window = ScannerWindow()
    window.show()
    return app.exec()
