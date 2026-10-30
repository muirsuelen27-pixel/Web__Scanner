#include "ui/Pages.h"

#include "core/LanguageManager.h"
#include "widgets/AnimatedButton.h"
#include "widgets/MetricCard.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDoubleSpinBox>
#include <QDebug>
#include <QEvent>
#include <QFile>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QJsonArray>
#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QSpinBox>
#include <QSplitter>
#include <QTabWidget>
#include <QTableView>
#include <QTextBrowser>
#include <QTextDocument>
#include <QPropertyAnimation>
#include <QVBoxLayout>

namespace {
QWidget *card(const QString &heading, QVBoxLayout **content, QWidget *parent = nullptr)
{
    auto *frame = new QFrame(parent);
    frame->setObjectName(QStringLiteral("panelCard"));
    auto *layout = new QVBoxLayout(frame);
    layout->setContentsMargins(17, 15, 17, 15);
    auto *title = new QLabel(heading, frame);
    title->setObjectName(QStringLiteral("cardHeading"));
    layout->addWidget(title);
    *content = layout;
    return frame;
}

void configureTable(QTableView *table)
{
    table->setAlternatingRowColors(true);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setSortingEnabled(true);
    table->verticalHeader()->hide();
    table->horizontalHeader()->setStretchLastSection(true);
    table->setAccessibleName(QObject::tr("Results table"));
}
}

AnalysisPage::AnalysisPage(QWidget *parent) : QWidget(parent)
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(13);

    QVBoxLayout *targetLayout{};
    auto *targetCard = card(tr("Scan target"), &targetLayout, this);
    m_targetTitle = qobject_cast<QLabel *>(targetLayout->itemAt(0)->widget());
    auto *targetRow = new QHBoxLayout;
    m_target = new QLineEdit(targetCard);
    m_target->setPlaceholderText(QStringLiteral("https://example.com"));
    m_target->setAccessibleName(tr("Authorized scan target URL"));
    m_scanButton = new AnimatedButton(targetCard);
    m_scanButton->setObjectName(QStringLiteral("primaryButton"));
    m_scanButton->setMinimumHeight(42);
    targetRow->addWidget(m_target, 1);
    targetRow->addWidget(m_scanButton);
    targetLayout->addLayout(targetRow);
    auto *moduleRow = new QHBoxLayout;
    m_dns = new QCheckBox(targetCard);
    m_http = new QCheckBox(targetCard);
    m_headers = new QCheckBox(targetCard);
    m_tls = new QCheckBox(targetCard);
    for (auto *check : {m_dns, m_http, m_headers, m_tls}) {
        check->setChecked(true);
        moduleRow->addWidget(check);
    }
    moduleRow->addStretch(1);
    targetLayout->addLayout(moduleRow);
    m_progressLabel = new QLabel(targetCard);
    m_progress = new QProgressBar(targetCard);
    m_progress->setRange(0, 100);
    m_progress->setTextVisible(false);
    targetLayout->addWidget(m_progressLabel);
    targetLayout->addWidget(m_progress);
    layout->addWidget(targetCard);

    auto *metricRow = new QHBoxLayout;
    const QStringList metricNames{tr("Observed risk"), tr("Findings"), tr("Security headers"), tr("Duration")};
    const QStringList metricColors{QStringLiteral("risk"), QStringLiteral("findings"),
                                   QStringLiteral("headers"), QStringLiteral("duration")};
    for (int index = 0; index < metricNames.size(); ++index) {
        auto *metric = new MetricCard(metricNames.at(index), metricColors.at(index), this);
        m_metrics.append(metric);
        metricRow->addWidget(metric, 1);
        metric->animateIn(index * 70);
    }
    layout->addLayout(metricRow);

    auto *filterRow = new QHBoxLayout;
    m_filter = new QLineEdit(this);
    m_filter->setPlaceholderText(tr("Search findings and technologies"));
    m_severityFilter = new QComboBox(this);
    m_confidenceFilter = new QComboBox(this);
    m_moduleFilter = new QComboBox(this);
    m_severityFilter->addItems({tr("All severities"), QStringLiteral("CRITICAL"), QStringLiteral("HIGH"),
                                QStringLiteral("MEDIUM"), QStringLiteral("LOW"), QStringLiteral("INFO")});
    m_confidenceFilter->addItems({tr("All confidence levels"), QStringLiteral("HIGH"),
                                  QStringLiteral("MEDIUM"), QStringLiteral("LOW")});
    m_moduleFilter->addItem(tr("All modules"), QString{});
    m_moduleFilter->addItem(tr("DNS"), QStringLiteral("dns"));
    m_moduleFilter->addItem(tr("HTTP"), QStringLiteral("http"));
    m_moduleFilter->addItem(tr("Security headers"), QStringLiteral("headers"));
    m_moduleFilter->addItem(tr("TLS"), QStringLiteral("tls"));
    filterRow->addWidget(m_filter, 1);
    filterRow->addWidget(m_severityFilter);
    filterRow->addWidget(m_confidenceFilter);
    filterRow->addWidget(m_moduleFilter);
    layout->addLayout(filterRow);

    m_findings = new FindingTableModel(this);
    m_findingProxy = new FindingFilterProxyModel(this);
    m_findingProxy->setSourceModel(m_findings);
    m_technologies = new TechnologyTableModel(this);
    m_technologyProxy = new QSortFilterProxyModel(this);
    m_technologyProxy->setSourceModel(m_technologies);
    m_technologyProxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_technologyProxy->setFilterKeyColumn(-1);
    m_findingsView = new QTableView(this);
    m_findingsView->setModel(m_findingProxy);
    configureTable(m_findingsView);
    m_findingsView->horizontalHeader()->setSectionResizeMode(FindingTableModel::Title, QHeaderView::Stretch);
    m_technologyView = new QTableView(this);
    m_technologyView->setModel(m_technologyProxy);
    configureTable(m_technologyView);
    m_technologyView->horizontalHeader()->setSectionResizeMode(TechnologyTableModel::Evidence, QHeaderView::Stretch);
    m_tabs = new QTabWidget(this);
    m_tabs->addTab(m_findingsView, QString{});
    m_tabs->addTab(m_technologyView, QIcon(QStringLiteral(":/assets/icons/technology.svg")), QString{});

    auto *splitter = new QSplitter(Qt::Horizontal, this);
    auto *resultsPanel = new QWidget(splitter);
    auto *resultsLayout = new QVBoxLayout(resultsPanel);
    resultsLayout->setContentsMargins(0, 0, 0, 0);
    resultsLayout->addWidget(m_tabs, 1);
    auto *buttonRow = new QHBoxLayout;
    m_jsonButton = new QPushButton(resultsPanel);
    m_jsonButton->setIcon(QIcon(QStringLiteral(":/assets/icons/export.svg")));
    m_pdfButton = new QPushButton(resultsPanel);
    m_pdfButton->setIcon(QIcon(QStringLiteral(":/assets/icons/export.svg")));
    m_aiButton = new AnimatedButton(resultsPanel);
    m_aiButton->setObjectName(QStringLiteral("primaryButton"));
    for (auto *button : {m_jsonButton, m_pdfButton, m_aiButton}) {
        button->setEnabled(false);
        buttonRow->addWidget(button);
    }
    buttonRow->addStretch(1);
    resultsLayout->addLayout(buttonRow);
    auto *detailPanel = new QWidget(splitter);
    auto *detailLayout = new QVBoxLayout(detailPanel);
    m_detail = new QLabel(tr("Select a finding to inspect its evidence."), detailPanel);
    m_detail->setObjectName(QStringLiteral("cardHeading"));
    m_detail->setWordWrap(true);
    m_detailText = new QTextBrowser(detailPanel);
    m_detailText->setOpenExternalLinks(false);
    detailLayout->addWidget(m_detail);
    detailLayout->addWidget(m_detailText, 1);
    splitter->addWidget(resultsPanel);
    splitter->addWidget(detailPanel);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);
    layout->addWidget(splitter, 1);

    connect(m_scanButton, &QPushButton::clicked, this, &AnalysisPage::startScan);
    connect(m_target, &QLineEdit::returnPressed, this, &AnalysisPage::startScan);
    connect(m_findingsView, &QTableView::clicked, this, &AnalysisPage::showFindingDetails);
    connect(m_filter, &QLineEdit::textChanged, this, [this](const QString &text) {
        m_findingProxy->setFilterFixedString(text);
        m_technologyProxy->setFilterFixedString(text);
    });
    connect(m_severityFilter, &QComboBox::currentTextChanged, m_findingProxy, &FindingFilterProxyModel::setSeverityFilter);
    connect(m_confidenceFilter, &QComboBox::currentTextChanged, m_findingProxy, &FindingFilterProxyModel::setConfidenceFilter);
    connect(m_moduleFilter, &QComboBox::currentIndexChanged, this, [this] {
        m_findingProxy->setModuleFilter(m_moduleFilter->currentData().toString());
    });
    connect(m_jsonButton, &QPushButton::clicked, this, [this] { emit exportRequested(QStringLiteral("json"), m_result); });
    connect(m_pdfButton, &QPushButton::clicked, this, [this] { emit exportRequested(QStringLiteral("pdf"), m_result); });
    connect(m_aiButton, &QPushButton::clicked, this, [this] { emit summaryRequested(m_result); });
    connect(LanguageManager::instance(), &LanguageManager::languageChanged, this, [this] {
        m_findings->retranslateHeaders();
        m_technologies->retranslateHeaders();
    });
    retranslateUi();
    setResult({});
}

void AnalysisPage::startScan()
{
    QJsonArray modules;
    if (m_dns->isChecked()) modules.append(QStringLiteral("dns"));
    if (m_http->isChecked()) modules.append(QStringLiteral("http"));
    if (m_headers->isChecked()) modules.append(QStringLiteral("headers"));
    if (m_tls->isChecked()) modules.append(QStringLiteral("tls"));
    QJsonObject request{
        {QStringLiteral("target"), m_target->text().trimmed()},
        {QStringLiteral("modules"), modules},
    };
    emit scanRequested(request);
}

void AnalysisPage::setResult(const QJsonObject &result)
{
    m_result = result;
    m_summary = result.value(QStringLiteral("executive_summary")).toString();
    const auto metadata = result.value(QStringLiteral("metadata")).toObject();
    m_findings->setFindings(result.value(QStringLiteral("findings")).toArray(),
                            metadata.value(QStringLiteral("finding_modules")).toArray());
    m_technologies->setTechnologies(metadata.value(QStringLiteral("technologies")).toArray());
    m_jsonButton->setEnabled(!result.isEmpty());
    m_pdfButton->setEnabled(!result.isEmpty());
    m_aiButton->setEnabled(!result.isEmpty());
    if (m_summary.isEmpty()) {
        m_detail->setText(tr("Select a finding to inspect its evidence."));
        m_detailText->clear();
    } else {
        setSummary(m_summary);
    }
    updateMetrics();
}

void AnalysisPage::updateMetrics()
{
    if (m_result.isEmpty()) {
        for (auto *metric : m_metrics) metric->setValue(QStringLiteral("—"));
        return;
    }
    const auto findings = m_result.value(QStringLiteral("findings")).toArray();
    const auto metadata = m_result.value(QStringLiteral("metadata")).toObject();
    const auto counts = m_result.value(QStringLiteral("counts")).toObject();
    const auto securityHeaders = metadata.value(QStringLiteral("security_headers")).toObject();
    const auto durationMs = metadata.value(QStringLiteral("http")).toObject().value(QStringLiteral("elapsed_ms")).toInt();
    m_metrics.at(0)->setValue(m_result.value(QStringLiteral("risk_level")).toString());
    m_metrics.at(1)->setValue(QString::number(findings.size()));
    m_metrics.at(2)->setValue(QString::number(securityHeaders.value(QStringLiteral("present")).toArray().size()));
    m_metrics.at(3)->setValue(durationMs > 0 ? tr("%1 ms").arg(durationMs) : QStringLiteral("—"));
    Q_UNUSED(counts);
}

void AnalysisPage::showFindingDetails(const QModelIndex &proxyIndex)
{
    const auto sourceIndex = m_findingProxy->mapToSource(proxyIndex);
    const auto finding = m_findings->findingAt(sourceIndex.row());
    m_detail->setText(finding.value(QStringLiteral("title")).toString());
    QString html = QStringLiteral(
        "<h3>%1</h3><p><b>%2:</b> %3 &nbsp; <b>%4:</b> %5</p>"
        "<h4>%6</h4><p>%7</p><h4>%8</h4><p>%9</p>"
        "<h4>%10</h4><p>%11</p><h4>%12</h4><p>%13</p>");
    const QStringList values{
        finding.value(QStringLiteral("title")).toString().toHtmlEscaped(),
        tr("Severity"), finding.value(QStringLiteral("severity")).toString().toHtmlEscaped(),
        tr("Confidence"), finding.value(QStringLiteral("confidence")).toString().toHtmlEscaped(),
        tr("Description"), finding.value(QStringLiteral("description")).toString().toHtmlEscaped(),
        tr("Evidence"), finding.value(QStringLiteral("evidence")).toString().toHtmlEscaped(),
        tr("Impact"), finding.value(QStringLiteral("impact")).toString().toHtmlEscaped(),
        tr("Recommendation"), finding.value(QStringLiteral("recommendation")).toString().toHtmlEscaped(),
    };
    for (const auto &value : values)
        html = html.arg(value);
    m_detailText->setHtml(html);
}

void AnalysisPage::setGlobalFilter(const QString &text)
{
    m_filter->setText(text);
}

void AnalysisPage::setProgress(const QString &label, int step, int total)
{
    m_progressLabel->setText(label);
    const int range = qMax(1, total);
    if (m_progress->maximum() != range)
        m_progress->setRange(0, range);
    auto *animation = new QPropertyAnimation(m_progress, "value", this);
    animation->setDuration(180);
    animation->setStartValue(m_progress->value());
    animation->setEndValue(qBound(0, step, range));
    animation->setEasingCurve(QEasingCurve::OutCubic);
    animation->start(QAbstractAnimation::DeleteWhenStopped);
}

void AnalysisPage::setBusy(bool busy)
{
    m_scanButton->setEnabled(!busy);
    if (!busy && m_progress->value() >= m_progress->maximum())
        m_progress->setValue(m_progress->maximum());
}

void AnalysisPage::setCompactMetrics(bool compact)
{
    for (auto *metric : m_metrics)
        metric->setCompact(compact);
}

void AnalysisPage::setTarget(const QString &target) { m_target->setText(target); }

QJsonObject AnalysisPage::currentResult() const { return m_result; }

void AnalysisPage::setSummary(const QString &summary)
{
    m_summary = summary;
    m_result.insert(QStringLiteral("executive_summary"), summary);
    m_detail->setText(tr("AI summary"));
    m_detailText->setHtml(QStringLiteral("<h3>%1</h3><p>%2</p>")
        .arg(tr("AI summary"), summary.toHtmlEscaped().replace(QLatin1Char('\n'), QStringLiteral("<br/>"))));
}

void AnalysisPage::changeEvent(QEvent *event)
{
    if (event->type() == QEvent::LanguageChange)
        retranslateUi();
    QWidget::changeEvent(event);
}

void AnalysisPage::retranslateUi()
{
    m_findings->retranslateHeaders();
    m_technologies->retranslateHeaders();
    if (m_targetTitle) m_targetTitle->setText(tr("Scan target"));
    const QStringList metricNames{tr("Observed risk"), tr("Findings"), tr("Security headers"), tr("Duration")};
    for (int index = 0; index < m_metrics.size(); ++index)
        m_metrics.at(index)->setTitle(metricNames.at(index));
    m_scanButton->setText(tr("Start analysis"));
    m_jsonButton->setText(tr("Export JSON"));
    m_pdfButton->setText(tr("Export PDF"));
    m_aiButton->setText(tr("AI summary"));
    m_dns->setText(tr("DNS and domain"));
    m_http->setText(tr("HTTP"));
    m_headers->setText(tr("Security headers"));
    m_tls->setText(tr("TLS"));
    m_filter->setPlaceholderText(tr("Search findings and technologies"));
    m_detail->setText(tr("Select a finding to inspect its evidence."));
    m_progressLabel->setText(tr("Ready for an authorized assessment."));
    m_tabs->setTabText(0, tr("Findings"));
    m_tabs->setTabText(1, tr("Technologies"));
    m_severityFilter->setItemText(0, tr("All severities"));
    m_confidenceFilter->setItemText(0, tr("All confidence levels"));
    m_moduleFilter->setItemText(0, tr("All modules"));
    m_moduleFilter->setItemText(1, tr("DNS"));
    m_moduleFilter->setItemText(2, tr("HTTP"));
    m_moduleFilter->setItemText(3, tr("Security headers"));
    m_moduleFilter->setItemText(4, tr("TLS"));
    if (!m_summary.isEmpty())
        setSummary(m_summary);
    else if (m_findingsView->currentIndex().isValid())
        showFindingDetails(m_findingsView->currentIndex());
}

HistoryPage::HistoryPage(QWidget *parent) : QWidget(parent)
{
    auto *layout = new QVBoxLayout(this);
    auto *toolbar = new QHBoxLayout;
    m_filter = new QLineEdit(this);
    m_filter->setPlaceholderText(tr("Search saved reports"));
    auto *refresh = new QPushButton(this);
    refresh->setIcon(QIcon(QStringLiteral(":/assets/icons/refresh.svg")));
    refresh->setAccessibleName(tr("Refresh history"));
    toolbar->addWidget(m_filter, 1);
    toolbar->addWidget(refresh);
    layout->addLayout(toolbar);

    m_model = new HistoryTableModel(this);
    m_proxy = new QSortFilterProxyModel(this);
    m_proxy->setSourceModel(m_model);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(-1);
    m_table = new QTableView(this);
    m_table->setModel(m_proxy);
    configureTable(m_table);
    m_table->horizontalHeader()->setSectionResizeMode(HistoryTableModel::Target, QHeaderView::Stretch);
    layout->addWidget(m_table, 2);
    m_detail = new QTextBrowser(this);
    m_detail->setObjectName(QStringLiteral("panelCard"));
    m_detail->setMinimumHeight(125);
    layout->addWidget(m_detail, 1);
    auto *actions = new QHBoxLayout;
    m_jsonButton = new QPushButton(this);
    m_pdfButton = new QPushButton(this);
    m_deleteButton = new QPushButton(this);
    m_deleteButton->setIcon(QIcon(QStringLiteral(":/assets/icons/delete.svg")));
    m_clearButton = new QPushButton(this);
    for (auto *button : {m_jsonButton, m_pdfButton, m_deleteButton, m_clearButton}) {
        button->setEnabled(false);
        actions->addWidget(button);
    }
    actions->addStretch(1);
    layout->addLayout(actions);
    connect(refresh, &QPushButton::clicked, this, &HistoryPage::refreshRequested);
    connect(m_filter, &QLineEdit::textChanged, m_proxy, &QSortFilterProxyModel::setFilterFixedString);
    connect(m_table, &QTableView::clicked, this, &HistoryPage::showSelected);
    connect(m_jsonButton, &QPushButton::clicked, this, [this] {
        emit exportRequested(QStringLiteral("json"), m_model->recordAt(m_proxy->mapToSource(m_table->currentIndex()).row()));
    });
    connect(m_pdfButton, &QPushButton::clicked, this, [this] {
        emit exportRequested(QStringLiteral("pdf"), m_model->recordAt(m_proxy->mapToSource(m_table->currentIndex()).row()));
    });
    connect(m_deleteButton, &QPushButton::clicked, this, [this] {
        const auto record = m_model->recordAt(m_proxy->mapToSource(m_table->currentIndex()).row());
        emit deleteRequested(record.value(QStringLiteral("path")).toString());
    });
    connect(m_clearButton, &QPushButton::clicked, this, &HistoryPage::clearRequested);
    connect(m_table->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, [this](const QModelIndex &current) { showSelected(current); });
    connect(LanguageManager::instance(), &LanguageManager::languageChanged, this, [this] {
        m_model->retranslateHeaders();
    });
    retranslateUi();
}

void HistoryPage::setRecords(const QJsonArray &records)
{
    m_model->setRecords(records);
    if (m_proxy->rowCount() > 0)
        m_table->selectRow(0);
    else {
        m_detail->clear();
        m_jsonButton->setEnabled(false);
        m_pdfButton->setEnabled(false);
        m_deleteButton->setEnabled(false);
        m_clearButton->setEnabled(false);
    }
}

void HistoryPage::setGlobalFilter(const QString &text) { m_filter->setText(text); }
void HistoryPage::selectFirst() { if (m_proxy->rowCount() > 0) m_table->selectRow(0); }
void HistoryPage::exportSelected(const QString &format)
{
    if (!m_table->currentIndex().isValid()) {
        m_table->selectRow(0);
        if (!m_table->currentIndex().isValid()) return;
    }
    const auto record = m_model->recordAt(m_proxy->mapToSource(m_table->currentIndex()).row());
    emit exportRequested(format, record);
}

void HistoryPage::showSelected(const QModelIndex &index)
{
    if (!index.isValid()) return;
    const auto record = m_model->recordAt(m_proxy->mapToSource(index).row());
    m_selectedRecord = record;
    const auto result = record.value(QStringLiteral("result")).toObject();
    QString html = QStringLiteral("<h3>%1</h3><p>%2</p><p>%3: %4</p>")
        .arg(result.value(QStringLiteral("target")).toString().toHtmlEscaped(),
             result.value(QStringLiteral("risk_level")).toString().toHtmlEscaped(),
             tr("Finding count"),
             QString::number(result.value(QStringLiteral("findings")).toArray().size()));
    const auto summary = record.value(QStringLiteral("executive_summary")).toString();
    if (!summary.isEmpty())
        html += QStringLiteral("<h4>%1</h4><p>%2</p>").arg(tr("AI summary"), summary.toHtmlEscaped());
    m_detail->setHtml(html);
    for (auto *button : {m_jsonButton, m_pdfButton, m_deleteButton, m_clearButton})
        button->setEnabled(true);
    emit selectedRecord(record);
    emitSelectedResult();
}

void HistoryPage::emitSelectedResult()
{
    if (!m_table->currentIndex().isValid()) return;
    const auto record = m_model->recordAt(m_proxy->mapToSource(m_table->currentIndex()).row());
    auto result = record.value(QStringLiteral("result")).toObject();
    const auto summary = record.value(QStringLiteral("executive_summary")).toString();
    if (!summary.isEmpty())
        result.insert(QStringLiteral("executive_summary"), summary);
    emit selectedResult(result);
}

void HistoryPage::changeEvent(QEvent *event)
{
    if (event->type() == QEvent::LanguageChange) retranslateUi();
    QWidget::changeEvent(event);
}

void HistoryPage::retranslateUi()
{
    m_model->retranslateHeaders();
    m_filter->setPlaceholderText(tr("Search saved reports"));
    m_jsonButton->setText(tr("Export JSON"));
    m_pdfButton->setText(tr("Export PDF"));
    m_deleteButton->setText(tr("Delete selected"));
    m_clearButton->setText(tr("Clear history"));
    if (m_table->currentIndex().isValid())
        showSelected(m_table->currentIndex());
}

KarenPage::KarenPage(QWidget *parent) : QWidget(parent)
{
    auto *layout = new QVBoxLayout(this);
    auto *suggestions = new QHBoxLayout;
    const QStringList promptKeys{
        tr("Summarize the latest report"), tr("What should I review first?"), tr("Explain the evidence"),
    };
    for (const auto &prompt : promptKeys) {
        auto *button = new QPushButton(prompt, this);
        m_suggestions.append(button);
        suggestions->addWidget(button);
        connect(button, &QPushButton::clicked, this, [this, prompt] {
            m_input->setText(prompt);
            sendMessage();
        });
    }
    suggestions->addStretch(1);
    layout->addLayout(suggestions);
    m_messages = new QTextBrowser(this);
    m_messages->setObjectName(QStringLiteral("panelCard"));
    m_messages->setAccessibleName(tr("Karen conversation"));
    QFile bubbleStyle(QStringLiteral(":/themes/chat.css"));
    if (!bubbleStyle.open(QIODevice::ReadOnly))
        qWarning("Could not load the Karen chat stylesheet resource.");
    else
        m_messages->document()->setDefaultStyleSheet(QString::fromUtf8(bubbleStyle.readAll()));
    layout->addWidget(m_messages, 1);
    m_clear = new QPushButton(this);
    layout->addWidget(m_clear, 0, Qt::AlignRight);
    auto *inputRow = new QHBoxLayout;
    m_input = new QLineEdit(this);
    m_send = new AnimatedButton(this);
    m_send->setObjectName(QStringLiteral("primaryButton"));
    inputRow->addWidget(m_input, 1);
    inputRow->addWidget(m_send);
    layout->addLayout(inputRow);
    connect(m_send, &QPushButton::clicked, this, &KarenPage::sendMessage);
    connect(m_input, &QLineEdit::returnPressed, this, &KarenPage::sendMessage);
    connect(m_clear, &QPushButton::clicked, this, [this] {
        m_history = {};
        m_messages->clear();
    });
    retranslateUi();
}

void KarenPage::setResultContext(const QJsonObject &result) { m_result = result; }

void KarenPage::sendMessage()
{
    const QString question = m_input->text().trimmed();
    if (question.isEmpty()) return;
    appendBubble(tr("You"), question, true);
    m_history.append(QJsonArray{QStringLiteral("user"), question});
    m_input->clear();
    emit chatRequested({
        {QStringLiteral("question"), question},
        {QStringLiteral("history"), m_history},
        {QStringLiteral("result"), m_result},
    });
}

void KarenPage::appendBubble(const QString &role, const QString &text, bool user)
{
    const QString markup = QStringLiteral(
        "<div class='bubble %1'>"
        "<b>%2</b><br/><span>%3</span></div>")
        .arg(user ? QStringLiteral("userBubble") : QStringLiteral("assistantBubble"),
             role.toHtmlEscaped(),
             text.toHtmlEscaped().replace(QLatin1Char('\n'), QStringLiteral("<br/>")));
    m_messages->append(markup);
}

void KarenPage::appendAnswer(const QString &answer)
{
    appendBubble(tr("Karen"), answer, false);
    m_history.append(QJsonArray{QStringLiteral("assistant"), answer});
}

void KarenPage::setBusy(bool busy) { m_send->setEnabled(!busy); }

void KarenPage::changeEvent(QEvent *event)
{
    if (event->type() == QEvent::LanguageChange) retranslateUi();
    QWidget::changeEvent(event);
}

void KarenPage::retranslateUi()
{
    const QStringList prompts{
        tr("Summarize the latest report"), tr("What should I review first?"), tr("Explain the evidence"),
    };
    for (int index = 0; index < m_suggestions.size(); ++index)
        m_suggestions.at(index)->setText(prompts.at(index));
    m_input->setPlaceholderText(tr("Ask Karen about the evidence in this report"));
    m_send->setText(tr("Send"));
    m_clear->setText(tr("Clear chat"));
    m_messages->clear();
    for (const auto &message : m_history) {
        const auto fields = message.toArray();
        if (fields.size() != 2) continue;
        const bool user = fields.at(0).toString() == QStringLiteral("user");
        appendBubble(user ? tr("You") : tr("Karen"), fields.at(1).toString(), user);
    }
}

SettingsPage::SettingsPage(QWidget *parent) : QWidget(parent)
{
    auto *layout = new QVBoxLayout(this);
    auto *panel = new QFrame(this);
    panel->setObjectName(QStringLiteral("settingsCard"));
    auto *form = new QFormLayout(panel);
    form->setContentsMargins(22, 20, 22, 20);
    form->setSpacing(15);

    m_timeout = new QDoubleSpinBox(panel);
    m_timeout->setRange(1, 120);
    m_timeout->setSuffix(tr(" s"));
    m_rate = new QDoubleSpinBox(panel);
    m_rate->setRange(0, 30);
    m_rate->setDecimals(2);
    m_rate->setSuffix(tr(" s"));
    m_redirects = new QSpinBox(panel);
    m_redirects->setRange(0, 20);
    m_model = new QLineEdit(panel);
    m_accent = new QComboBox(panel);
    m_accent->addItem(tr("Cyan"), QStringLiteral("cyan"));
    m_accent->addItem(tr("Indigo"), QStringLiteral("indigo"));
    m_accent->addItem(tr("Emerald"), QStringLiteral("emerald"));
    m_theme = new QComboBox(panel);
    m_theme->addItem(tr("Dark"), QStringLiteral("dark"));
    m_theme->addItem(tr("Light"), QStringLiteral("light"));
    m_theme->addItem(tr("Auto"), QStringLiteral("auto"));
    m_language = new QComboBox(panel);
    m_language->addItems({QStringLiteral("English"), QStringLiteral("Español"), QStringLiteral("Français")});
    m_language->setItemData(0, QStringLiteral("en"));
    m_language->setItemData(1, QStringLiteral("es"));
    m_language->setItemData(2, QStringLiteral("fr"));
    m_autoSummary = new QCheckBox(panel);
    m_compact = new QCheckBox(panel);
    m_save = new QPushButton(panel);
    m_save->setObjectName(QStringLiteral("primaryButton"));
    form->addRow(QString{}, m_timeout);
    form->addRow(QString{}, m_rate);
    form->addRow(QString{}, m_redirects);
    form->addRow(QString{}, m_model);
    form->addRow(QString{}, m_accent);
    form->addRow(QString{}, m_theme);
    form->addRow(QString{}, m_language);
    form->addRow(QString{}, m_autoSummary);
    form->addRow(QString{}, m_compact);
    form->addRow(m_save);
    layout->addWidget(panel);
    layout->addStretch(1);

    connect(m_save, &QPushButton::clicked, this, [this] {
        const auto value = settings();
        emit settingsChanged(value);
        emit themeRequested(value.value(QStringLiteral("theme")).toString(),
                            value.value(QStringLiteral("accent")).toString());
        emit languageRequested(value.value(QStringLiteral("language")).toString());
        emit compactMetricsChanged(value.value(QStringLiteral("compact_metrics")).toBool());
    });
    connect(m_accent, &QComboBox::currentTextChanged, this, [this](const QString &accent) {
        Q_UNUSED(accent);
        emit themeRequested(m_theme->currentData().toString(), m_accent->currentData().toString());
    });
    connect(m_theme, &QComboBox::currentTextChanged, this, [this](const QString &mode) {
        Q_UNUSED(mode);
        emit themeRequested(m_theme->currentData().toString(), m_accent->currentData().toString());
    });
    connect(m_language, &QComboBox::currentIndexChanged, this, [this] {
        emit languageRequested(m_language->currentData().toString());
    });
    connect(m_compact, &QCheckBox::toggled, this, &SettingsPage::compactMetricsChanged);
    retranslateUi();
}

void SettingsPage::loadSettings(const QJsonObject &settings)
{
    m_timeout->setValue(settings.value(QStringLiteral("timeout")).toDouble(10.0));
    m_rate->setValue(settings.value(QStringLiteral("rate_limit")).toDouble(0.0));
    m_redirects->setValue(settings.value(QStringLiteral("max_redirects")).toInt(5));
    m_model->setText(settings.value(QStringLiteral("ollama_model")).toString(QStringLiteral("qwen2.5:3b")));
    m_accent->setCurrentIndex(qMax(0, m_accent->findData(settings.value(QStringLiteral("accent")).toString(QStringLiteral("cyan")))));
    m_theme->setCurrentIndex(qMax(0, m_theme->findData(settings.value(QStringLiteral("theme")).toString(QStringLiteral("dark")))));
    const QString language = settings.value(QStringLiteral("language")).toString(QStringLiteral("en"));
    for (int index = 0; index < m_language->count(); ++index)
        if (m_language->itemData(index).toString() == language) m_language->setCurrentIndex(index);
    m_autoSummary->setChecked(settings.value(QStringLiteral("auto_ai_summary")).toBool());
    m_compact->setChecked(settings.value(QStringLiteral("compact_metrics")).toBool());
}

void SettingsPage::applySettings(const QJsonObject &settings) { loadSettings(settings); }

QJsonObject SettingsPage::settings() const
{
    return {
        {QStringLiteral("timeout"), m_timeout->value()},
        {QStringLiteral("rate_limit"), m_rate->value()},
        {QStringLiteral("max_redirects"), m_redirects->value()},
        {QStringLiteral("ollama_model"), m_model->text().trimmed()},
        {QStringLiteral("accent"), m_accent->currentData().toString()},
        {QStringLiteral("theme"), m_theme->currentData().toString()},
        {QStringLiteral("language"), m_language->currentData().toString()},
        {QStringLiteral("auto_ai_summary"), m_autoSummary->isChecked()},
        {QStringLiteral("compact_metrics"), m_compact->isChecked()},
    };
}

void SettingsPage::changeEvent(QEvent *event)
{
    if (event->type() == QEvent::LanguageChange) retranslateUi();
    QWidget::changeEvent(event);
}

void SettingsPage::retranslateUi()
{
    m_timeout->setSuffix(tr(" s"));
    m_rate->setSuffix(tr(" s"));
    m_autoSummary->setText(tr("Generate an AI summary after each scan"));
    m_compact->setText(tr("Compact metric cards"));
    m_save->setText(tr("Save settings"));
    m_accent->setItemText(0, tr("Cyan"));
    m_accent->setItemText(1, tr("Indigo"));
    m_accent->setItemText(2, tr("Emerald"));
    m_theme->setItemText(0, tr("Dark"));
    m_theme->setItemText(1, tr("Light"));
    m_theme->setItemText(2, tr("Auto"));
    auto *form = qobject_cast<QFormLayout *>(m_timeout->parentWidget()->layout());
    if (!form) return;
    form->setWidget(0, QFormLayout::LabelRole, new QLabel(tr("Request timeout"), form->parentWidget()));
    form->setWidget(1, QFormLayout::LabelRole, new QLabel(tr("Rate limit spacing"), form->parentWidget()));
    form->setWidget(2, QFormLayout::LabelRole, new QLabel(tr("Maximum redirects"), form->parentWidget()));
    form->setWidget(3, QFormLayout::LabelRole, new QLabel(tr("Ollama model"), form->parentWidget()));
    form->setWidget(4, QFormLayout::LabelRole, new QLabel(tr("Accent color"), form->parentWidget()));
    form->setWidget(5, QFormLayout::LabelRole, new QLabel(tr("Appearance"), form->parentWidget()));
    form->setWidget(6, QFormLayout::LabelRole, new QLabel(tr("Language"), form->parentWidget()));
}
