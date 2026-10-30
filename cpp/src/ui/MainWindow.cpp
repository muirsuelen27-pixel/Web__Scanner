#include "ui/MainWindow.h"

#include "core/BackendClient.h"
#include "core/LanguageManager.h"
#include "core/ThemeManager.h"
#include "ui/Pages.h"
#include "widgets/Sidebar.h"
#include "widgets/Toast.h"

#include <QApplication>
#include <QDebug>
#include <QComboBox>
#include <QFileDialog>
#include <QGraphicsOpacityEffect>
#include <QHBoxLayout>
#include <QIcon>
#include <QJsonArray>
#include <QKeySequence>
#include <QLineEdit>
#include <QMessageBox>
#include <QPropertyAnimation>
#include <QParallelAnimationGroup>
#include <QResizeEvent>
#include <QSettings>
#include <QShortcut>
#include <QStackedWidget>
#include <QStatusBar>
#include <QVBoxLayout>

MainWindow::MainWindow(const QString &target, QWidget *parent) : QMainWindow(parent), m_backend(new BackendClient(this))
{
    setObjectName(QStringLiteral("mainWindow"));
    setWindowTitle(tr("Web Scanner"));
    setMinimumSize(980, 680);
    resize(1440, 900);
    loadSettings();
    ThemeManager::instance()->setAccent(m_settings.value(QStringLiteral("accent")).toString(QStringLiteral("cyan")));
    ThemeManager::instance()->setMode(m_settings.value(QStringLiteral("theme")).toString(QStringLiteral("dark")));
    LanguageManager::instance()->setLanguage(m_settings.value(QStringLiteral("language")).toString(QStringLiteral("en")));
    buildUi();
    connectUi();
    ThemeManager::instance()->apply(this);
    m_analysis->setCompactMetrics(m_settings.value(QStringLiteral("compact_metrics")).toBool());
    m_analysis->setTarget(target);
    m_settingsPage->loadSettings(m_settings);
    showPage(0);
    beginRequest(QStringLiteral("ai.status"));
    requestHistory();
}

void MainWindow::buildUi()
{
    auto *root = new QWidget(this);
    auto *shell = new QHBoxLayout(root);
    shell->setContentsMargins(0, 0, 0, 0);
    shell->setSpacing(0);
    m_sidebar = new Sidebar(root);
    shell->addWidget(m_sidebar);

    auto *content = new QWidget(root);
    content->setObjectName(QStringLiteral("contentShell"));
    auto *contentLayout = new QVBoxLayout(content);
    contentLayout->setContentsMargins(30, 23, 30, 16);
    contentLayout->setSpacing(15);

    auto *header = new QHBoxLayout;
    auto *titles = new QVBoxLayout;
    m_pageTitle = new QLabel(content);
    m_pageTitle->setObjectName(QStringLiteral("pageTitle"));
    m_pageSubtitle = new QLabel(content);
    m_pageSubtitle->setObjectName(QStringLiteral("pageSubtitle"));
    titles->addWidget(m_pageTitle);
    titles->addWidget(m_pageSubtitle);
    header->addLayout(titles);
    header->addStretch(1);
    m_globalSearch = new QLineEdit(content);
    m_globalSearch->setObjectName(QStringLiteral("globalSearch"));
    m_globalSearch->setClearButtonEnabled(true);
    m_globalSearch->addAction(QIcon(QStringLiteral(":/assets/icons/search.svg")), QLineEdit::LeadingPosition);
    m_globalSearch->setMaximumWidth(390);
    m_globalSearch->setAccessibleName(tr("Search all findings, history, and technologies"));
    header->addWidget(m_globalSearch);
    contentLayout->addLayout(header);

    m_pages = new QStackedWidget(content);
    m_analysis = new AnalysisPage(m_pages);
    m_history = new HistoryPage(m_pages);
    m_karen = new KarenPage(m_pages);
    m_settingsPage = new SettingsPage(m_pages);
    m_pages->addWidget(m_analysis);
    m_pages->addWidget(m_history);
    m_pages->addWidget(m_karen);
    m_pages->addWidget(m_settingsPage);
    contentLayout->addWidget(m_pages, 1);
    shell->addWidget(content, 1);
    setCentralWidget(root);

    m_aiStatus = new QLabel(this);
    m_aiStatus->setObjectName(QStringLiteral("aiStatus"));
    statusBar()->addPermanentWidget(m_aiStatus);
    m_toast = new Toast(this);
}

void MainWindow::connectUi()
{
    connect(m_sidebar, &Sidebar::pageRequested, this, &MainWindow::showPage);
    connect(m_analysis, &AnalysisPage::scanRequested, this, [this](const QJsonObject &request) {
        QJsonObject payload = request;
        payload.insert(QStringLiteral("timeout"), m_settings.value(QStringLiteral("timeout")).toDouble(10));
        payload.insert(QStringLiteral("rate_limit"), m_settings.value(QStringLiteral("rate_limit")).toDouble());
        payload.insert(QStringLiteral("max_redirects"), m_settings.value(QStringLiteral("max_redirects")).toInt(5));
        beginRequest(QStringLiteral("scan"), payload);
        m_analysis->setBusy(true);
        m_analysis->setProgress(tr("Preparing assessment…"), 0, 1);
    });
    connect(m_analysis, &AnalysisPage::exportRequested, this, &MainWindow::requestExport);
    connect(m_analysis, &AnalysisPage::summaryRequested, this, [this](const QJsonObject &result) {
        beginRequest(QStringLiteral("ai.summary"), {
            {QStringLiteral("result"), result},
            {QStringLiteral("ollama_model"), m_settings.value(QStringLiteral("ollama_model"))},
        });
    });
    connect(m_history, &HistoryPage::refreshRequested, this, &MainWindow::refreshHistory);
    connect(m_history, &HistoryPage::selectedResult, this, [this](const QJsonObject &result) {
        m_currentResult = result;
        m_analysis->setResult(result);
        m_karen->setResultContext(result);
    });
    connect(m_history, &HistoryPage::selectedRecord, this, [this](const QJsonObject &record) {
        m_currentHistoryPath = record.value(QStringLiteral("path")).toString();
    });
    connect(m_history, &HistoryPage::exportRequested, this, &MainWindow::requestExport);
    connect(m_history, &HistoryPage::deleteRequested, this, [this](const QString &path) {
        const auto answer = QMessageBox::question(this, tr("Delete saved report"),
            tr("Delete this report from local history?"));
        if (answer == QMessageBox::Yes) {
            if (path == m_currentHistoryPath) m_currentHistoryPath.clear();
            beginRequest(QStringLiteral("history.delete"), {{QStringLiteral("path"), path}});
        }
    });
    connect(m_history, &HistoryPage::clearRequested, this, [this] {
        const auto answer = QMessageBox::question(this, tr("Clear history"),
            tr("Permanently remove all locally saved reports?"));
        if (answer == QMessageBox::Yes) {
            m_currentHistoryPath.clear();
            beginRequest(QStringLiteral("history.clear"));
        }
    });
    connect(m_karen, &KarenPage::chatRequested, this, [this](QJsonObject request) {
        request.insert(QStringLiteral("ollama_model"), m_settings.value(QStringLiteral("ollama_model")));
        m_karen->setBusy(true);
        beginRequest(QStringLiteral("ai.chat"), request);
    });
    connect(m_settingsPage, &SettingsPage::settingsChanged, this, &MainWindow::saveSettings);
    connect(m_settingsPage, &SettingsPage::themeRequested, this, [this](const QString &mode, const QString &accent) {
        ThemeManager::instance()->setMode(mode);
        ThemeManager::instance()->setAccent(accent);
        ThemeManager::instance()->apply(this);
    });
    connect(m_settingsPage, &SettingsPage::languageRequested, this, [](const QString &language) {
        if (!LanguageManager::instance()->setLanguage(language))
            qWarning("Failed to load requested Qt translation catalog.");
    });
    connect(m_settingsPage, &SettingsPage::compactMetricsChanged, m_analysis, &AnalysisPage::setCompactMetrics);
    connect(ThemeManager::instance(), &ThemeManager::themeChanged, this,
            [this] { ThemeManager::instance()->apply(this); });
    connect(m_globalSearch, &QLineEdit::textChanged, this, [this](const QString &text) {
        m_analysis->setGlobalFilter(text);
        m_history->setGlobalFilter(text);
    });
    connect(m_backend, &BackendClient::responseReceived, this, &MainWindow::handleResponse);
    connect(m_backend, &BackendClient::progressReceived, this,
            [this](const QString &, const QString &backendLabel, int step, int total) {
                QString label = backendLabel;
                if (backendLabel == QStringLiteral("Resolviendo DNS")) label = tr("Resolving DNS");
                else if (backendLabel == QStringLiteral("Observando conexión HTTP")) label = tr("Observing HTTP response");
                else if (backendLabel == QStringLiteral("Evaluando headers de seguridad")) label = tr("Checking security headers");
                else if (backendLabel == QStringLiteral("Validando TLS")) label = tr("Checking TLS");
                m_analysis->setProgress(label, step, total);
            });
    connect(m_backend, &BackendClient::backendError, this, [this](const QString &message) {
        if (!message.trimmed().isEmpty())
            m_toast->showMessage(message, true);
    });

    auto *scanShortcut = new QShortcut(QKeySequence(QStringLiteral("Ctrl+R")), this);
    connect(scanShortcut, &QShortcut::activated, this, &MainWindow::startScan);
    auto *historyShortcut = new QShortcut(QKeySequence(QStringLiteral("Ctrl+H")), this);
    connect(historyShortcut, &QShortcut::activated, this, &MainWindow::refreshHistory);
    connect(historyShortcut, &QShortcut::activated, this, [this] { showPage(1); });
    auto *searchShortcut = new QShortcut(QKeySequence(QStringLiteral("Ctrl+K")), this);
    connect(searchShortcut, &QShortcut::activated, this, [this] {
        m_globalSearch->setFocus();
        m_globalSearch->selectAll();
    });
    auto *karenShortcut = new QShortcut(QKeySequence(QStringLiteral("Ctrl+Shift+K")), this);
    connect(karenShortcut, &QShortcut::activated, this, [this] { showPage(2); });
    auto *settingsShortcut = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_Comma), this);
    connect(settingsShortcut, &QShortcut::activated, this, [this] { showPage(3); });
    auto *exportShortcut = new QShortcut(QKeySequence(QStringLiteral("Ctrl+E")), this);
    connect(exportShortcut, &QShortcut::activated, this, &MainWindow::exportCurrent);
    auto *refreshShortcut = new QShortcut(QKeySequence(Qt::Key_F5), this);
    connect(refreshShortcut, &QShortcut::activated, this, &MainWindow::refreshHistory);
}

void MainWindow::showPage(int index)
{
    if (index < 0 || index >= m_pages->count()) return;
    m_sidebar->setCurrentPage(index);
    const int previousIndex = m_pages->currentIndex();
    m_pages->setCurrentIndex(index);
    auto *page = m_pages->currentWidget();
    if (previousIndex != index) {
        auto *opacity = new QGraphicsOpacityEffect(page);
        page->setGraphicsEffect(opacity);
        opacity->setOpacity(0.0);
        const QRect target = m_pages->contentsRect();
        page->setGeometry(target.translated(12, 0));
        auto *group = new QParallelAnimationGroup(page);
        auto *fade = new QPropertyAnimation(opacity, "opacity", group);
        fade->setStartValue(0.0);
        fade->setEndValue(1.0);
        fade->setDuration(190);
        fade->setEasingCurve(QEasingCurve::OutCubic);
        auto *slide = new QPropertyAnimation(page, "geometry", group);
        slide->setStartValue(page->geometry());
        slide->setEndValue(target);
        slide->setDuration(210);
        slide->setEasingCurve(QEasingCurve::OutCubic);
        connect(group, &QParallelAnimationGroup::finished, this, [page] { page->setGraphicsEffect(nullptr); });
        group->start(QAbstractAnimation::DeleteWhenStopped);
    }
    const QStringList titles{tr("Analysis center"), tr("History and reports"), tr("Karen assistant"), tr("Settings")};
    const QStringList subtitles{
        tr("Evidence-led checks. Reproducible results."),
        tr("Review and export locally saved assessments."),
        tr("Ask questions about the evidence in your report."),
        tr("Configure privacy-conscious scan and display preferences."),
    };
    m_pageTitle->setText(titles.at(index));
    m_pageSubtitle->setText(subtitles.at(index));
}

void MainWindow::retranslateUi()
{
    setWindowTitle(tr("Web Scanner"));
    m_globalSearch->setPlaceholderText(tr("Search all findings, history, and technologies (Ctrl+K)"));
    showPage(m_pages->currentIndex());
    m_aiStatus->setText(m_aiAvailable
        ? tr("AI available · Ollama %1").arg(m_ollamaAvailable ? tr("connected") : tr("not connected"))
        : tr("AI not configured"));
}

void MainWindow::loadSettings()
{
    QSettings settings(QStringLiteral("WebScanner"), QStringLiteral("WebScannerDesktop"));
    m_settings = {
        {QStringLiteral("timeout"), settings.value(QStringLiteral("scan/timeout"), 10.0).toDouble()},
        {QStringLiteral("rate_limit"), settings.value(QStringLiteral("scan/rate_limit"), 0.0).toDouble()},
        {QStringLiteral("max_redirects"), settings.value(QStringLiteral("scan/max_redirects"), 5).toInt()},
        {QStringLiteral("ollama_model"), settings.value(QStringLiteral("ai/ollama_model"), QStringLiteral("qwen2.5:3b")).toString()},
        {QStringLiteral("accent"), settings.value(QStringLiteral("appearance/accent"), QStringLiteral("cyan")).toString()},
        {QStringLiteral("theme"), settings.value(QStringLiteral("appearance/theme"), QStringLiteral("dark")).toString()},
        {QStringLiteral("language"), settings.value(QStringLiteral("appearance/language"), QStringLiteral("en")).toString()},
        {QStringLiteral("auto_ai_summary"), settings.value(QStringLiteral("ai/auto_summary"), false).toBool()},
        {QStringLiteral("compact_metrics"), settings.value(QStringLiteral("appearance/compact_metrics"), false).toBool()},
    };
}

void MainWindow::saveSettings(const QJsonObject &settings)
{
    QSettings stored(QStringLiteral("WebScanner"), QStringLiteral("WebScannerDesktop"));
    stored.setValue(QStringLiteral("scan/timeout"), settings.value(QStringLiteral("timeout")).toDouble());
    stored.setValue(QStringLiteral("scan/rate_limit"), settings.value(QStringLiteral("rate_limit")).toDouble());
    stored.setValue(QStringLiteral("scan/max_redirects"), settings.value(QStringLiteral("max_redirects")).toInt());
    stored.setValue(QStringLiteral("ai/ollama_model"), settings.value(QStringLiteral("ollama_model")).toString());
    stored.setValue(QStringLiteral("appearance/accent"), settings.value(QStringLiteral("accent")).toString());
    stored.setValue(QStringLiteral("appearance/theme"), settings.value(QStringLiteral("theme")).toString());
    stored.setValue(QStringLiteral("appearance/language"), settings.value(QStringLiteral("language")).toString());
    stored.setValue(QStringLiteral("ai/auto_summary"), settings.value(QStringLiteral("auto_ai_summary")).toBool());
    stored.setValue(QStringLiteral("appearance/compact_metrics"), settings.value(QStringLiteral("compact_metrics")).toBool());
    stored.sync();
    if (stored.status() != QSettings::NoError) {
        m_toast->showMessage(tr("Settings could not be saved."), true);
        return;
    }
    m_settings = settings;
    m_toast->showMessage(tr("Settings saved."));
}

void MainWindow::beginRequest(const QString &operation, const QJsonObject &payload)
{
    const QString id = m_backend->request(operation, payload);
    m_requestKinds.insert(id, operation);
}

void MainWindow::handleResponse(const QString &id, const QJsonObject &response)
{
    const QString operation = m_requestKinds.take(id);
    if (!response.value(QStringLiteral("ok")).toBool()) {
        const QString message = response.value(QStringLiteral("error")).toString(tr("The request failed."));
        if (operation == QStringLiteral("scan")) m_analysis->setBusy(false);
        if (operation == QStringLiteral("ai.chat")) m_karen->setBusy(false);
        m_toast->showMessage(message, true);
        return;
    }
    if (operation == QStringLiteral("scan")) {
        m_analysis->setBusy(false);
        m_currentResult = response.value(QStringLiteral("result")).toObject();
        m_currentHistoryPath = response.value(QStringLiteral("history_path")).toString();
        m_analysis->setResult(m_currentResult);
        m_karen->setResultContext(m_currentResult);
        m_toast->showMessage(tr("Assessment completed and saved to local history."));
        requestHistory();
        if (m_settings.value(QStringLiteral("auto_ai_summary")).toBool()) {
            beginRequest(QStringLiteral("ai.summary"), {
                {QStringLiteral("result"), m_currentResult},
                {QStringLiteral("ollama_model"), m_settings.value(QStringLiteral("ollama_model"))},
            });
        }
    } else if (operation == QStringLiteral("history")) {
        const auto records = response.value(QStringLiteral("records")).toArray();
        m_history->setRecords(records);
    } else if (operation == QStringLiteral("history.delete") || operation == QStringLiteral("history.clear")) {
        if (operation == QStringLiteral("history.clear"))
            m_currentHistoryPath.clear();
        m_toast->showMessage(tr("Local history updated."));
        requestHistory();
    } else if (operation == QStringLiteral("history.update")) {
        requestHistory();
    } else if (operation == QStringLiteral("export.json") || operation == QStringLiteral("export.pdf")) {
        m_toast->showMessage(tr("Report exported to %1").arg(response.value(QStringLiteral("path")).toString()));
    } else if (operation == QStringLiteral("ai.summary")) {
        const QString summary = response.value(QStringLiteral("summary")).toString();
        m_analysis->setSummary(summary);
        m_currentResult.insert(QStringLiteral("executive_summary"), summary);
        if (!m_currentHistoryPath.isEmpty())
            beginRequest(QStringLiteral("history.update"), {
                {QStringLiteral("path"), m_currentHistoryPath},
                {QStringLiteral("result"), m_currentResult},
                {QStringLiteral("executive_summary"), summary},
            });
        m_toast->showMessage(tr("AI summary is ready."));
    } else if (operation == QStringLiteral("ai.chat")) {
        m_karen->setBusy(false);
        m_karen->appendAnswer(response.value(QStringLiteral("answer")).toString());
    } else if (operation == QStringLiteral("ai.status")) {
        updateAiStatus(response);
    }
}

void MainWindow::updateAiStatus(const QJsonObject &response)
{
    m_ollamaAvailable = response.value(QStringLiteral("ollama_available")).toBool();
    m_aiAvailable = response.value(QStringLiteral("gemini_configured")).toBool() || m_ollamaAvailable;
    retranslateUi();
}

void MainWindow::requestHistory()
{
    beginRequest(QStringLiteral("history"));
}

void MainWindow::requestExport(const QString &format, const QJsonObject &record)
{
    const QString suffix = format == QStringLiteral("pdf") ? QStringLiteral("pdf") : QStringLiteral("json");
    const QString destination = QFileDialog::getSaveFileName(
        this, tr("Export report"), QStringLiteral("web_scanner_report.%1").arg(suffix),
        suffix == QStringLiteral("pdf") ? tr("PDF documents (*.pdf)") : tr("JSON files (*.json)"));
    if (destination.isEmpty()) return;
    QJsonObject payload{
        {QStringLiteral("destination"), destination},
        {QStringLiteral("result"), record.value(QStringLiteral("result")).isObject()
             ? record.value(QStringLiteral("result")) : QJsonValue(record)},
    };
    const QString summary = record.value(QStringLiteral("executive_summary")).toString();
    if (!summary.isEmpty())
        payload.insert(QStringLiteral("executive_summary"), summary);
    beginRequest(QStringLiteral("export.%1").arg(suffix), payload);
}

void MainWindow::startScan()
{
    showPage(0);
    m_analysis->startScan();
}

void MainWindow::refreshHistory()
{
    requestHistory();
}

void MainWindow::exportCurrent()
{
    if (m_pages->currentIndex() == 1) {
        m_history->exportSelected(QStringLiteral("json"));
        return;
    }
    if (m_currentResult.isEmpty()) {
        m_toast->showMessage(tr("Run an assessment or select a saved report first."));
        return;
    }
    requestExport(QStringLiteral("json"), m_currentResult);
}

void MainWindow::changeEvent(QEvent *event)
{
    if (event->type() == QEvent::LanguageChange)
        retranslateUi();
    QMainWindow::changeEvent(event);
}

void MainWindow::resizeEvent(QResizeEvent *event)
{
    QMainWindow::resizeEvent(event);
    m_sidebar->setCollapsed(width() < 1120);
}
