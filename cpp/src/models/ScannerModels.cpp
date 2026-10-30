#include "models/ScannerModels.h"

#include <QColor>
#include <QJsonValue>
#include <QStringList>

namespace {
QString text(const QJsonObject &object, const QString &key)
{
    return object.value(key).toString();
}

QVariant translatedHeader(const QStringList &headers, int section, Qt::Orientation orientation, int role)
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole || section < 0 || section >= headers.size())
        return {};
    return headers.at(section);
}
}

FindingTableModel::FindingTableModel(QObject *parent) : QAbstractTableModel(parent) {}

int FindingTableModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : m_findings.size();
}

int FindingTableModel::columnCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant FindingTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_findings.size())
        return {};
    const auto finding = m_findings.at(index.row()).toObject();
    if (role == Qt::TextAlignmentRole && index.column() != Title)
        return Qt::AlignCenter;
    if (role == Qt::ForegroundRole && index.column() == Severity) {
        const auto severity = text(finding, QStringLiteral("severity"));
        if (severity == QStringLiteral("CRITICAL")) return QColor(QStringLiteral("#F87171"));
        if (severity == QStringLiteral("HIGH")) return QColor(QStringLiteral("#FB923C"));
        if (severity == QStringLiteral("MEDIUM")) return QColor(QStringLiteral("#FBBF24"));
        if (severity == QStringLiteral("LOW")) return QColor(QStringLiteral("#60A5FA"));
        return QColor(QStringLiteral("#94A3B8"));
    }
    if (role != Qt::DisplayRole)
        return {};
    switch (index.column()) {
    case Severity: return text(finding, QStringLiteral("severity"));
    case Title: return text(finding, QStringLiteral("title"));
    case Confidence: return text(finding, QStringLiteral("confidence"));
    case Status: return text(finding, QStringLiteral("status"));
    case Module: {
        const auto module = finding.value(QStringLiteral("module")).toString();
        if (module == QStringLiteral("dns")) return tr("DNS");
        if (module == QStringLiteral("http")) return tr("HTTP");
        if (module == QStringLiteral("headers")) return tr("Security headers");
        if (module == QStringLiteral("tls")) return tr("TLS");
        return tr("General");
    }
    default: return {};
    }
}

QVariant FindingTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    return translatedHeader(
        {tr("Severity"), tr("Finding"), tr("Confidence"), tr("Status"), tr("Module")},
        section, orientation, role);
}

void FindingTableModel::setFindings(const QJsonArray &findings, const QJsonArray &modules)
{
    beginResetModel();
    m_findings = findings;
    for (qsizetype index = 0; index < m_findings.size(); ++index) {
        auto finding = m_findings.at(index).toObject();
        if (index < modules.size())
            finding.insert(QStringLiteral("module"), modules.at(index));
        m_findings.replace(index, finding);
    }
    endResetModel();
}

QJsonObject FindingTableModel::findingAt(int row) const
{
    return row >= 0 && row < m_findings.size() ? m_findings.at(row).toObject() : QJsonObject{};
}

void FindingTableModel::retranslateHeaders()
{
    emit headerDataChanged(Qt::Horizontal, 0, ColumnCount - 1);
    if (!m_findings.isEmpty())
        emit dataChanged(index(0, Module), index(m_findings.size() - 1, Module), {Qt::DisplayRole});
}

TechnologyTableModel::TechnologyTableModel(QObject *parent) : QAbstractTableModel(parent) {}

int TechnologyTableModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : m_technologies.size();
}

int TechnologyTableModel::columnCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant TechnologyTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_technologies.size() || role != Qt::DisplayRole)
        return {};
    const auto item = m_technologies.at(index.row()).toObject();
    switch (index.column()) {
    case Name: return text(item, QStringLiteral("name"));
    case Category: return text(item, QStringLiteral("category"));
    case Evidence: return text(item, QStringLiteral("evidence"));
    case Confidence: return text(item, QStringLiteral("confidence"));
    default: return {};
    }
}

QVariant TechnologyTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    return translatedHeader(
        {tr("Technology"), tr("Category"), tr("Evidence"), tr("Confidence")},
        section, orientation, role);
}

void TechnologyTableModel::setTechnologies(const QJsonArray &technologies)
{
    beginResetModel();
    m_technologies = technologies;
    endResetModel();
}

void TechnologyTableModel::retranslateHeaders()
{
    emit headerDataChanged(Qt::Horizontal, 0, ColumnCount - 1);
}

HistoryTableModel::HistoryTableModel(QObject *parent) : QAbstractTableModel(parent) {}

int HistoryTableModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : m_records.size();
}

int HistoryTableModel::columnCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant HistoryTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_records.size())
        return {};
    const auto record = m_records.at(index.row()).toObject();
    const auto result = record.value(QStringLiteral("result")).toObject();
    if (role != Qt::DisplayRole)
        return {};
    switch (index.column()) {
    case Started: return result.value(QStringLiteral("started_at")).toString().replace(QLatin1Char('T'), QLatin1Char(' ')).left(19);
    case Target: return text(result, QStringLiteral("target"));
    case Risk: return text(result, QStringLiteral("risk_level"));
    case FindingCount: return result.value(QStringLiteral("findings")).toArray().size();
    default: return {};
    }
}

QVariant HistoryTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    return translatedHeader(
        {tr("Started"), tr("Target"), tr("Observed risk"), tr("Findings")},
        section, orientation, role);
}

void HistoryTableModel::setRecords(const QJsonArray &records)
{
    beginResetModel();
    m_records = records;
    endResetModel();
}

QJsonObject HistoryTableModel::recordAt(int row) const
{
    return row >= 0 && row < m_records.size() ? m_records.at(row).toObject() : QJsonObject{};
}

void HistoryTableModel::retranslateHeaders()
{
    emit headerDataChanged(Qt::Horizontal, 0, ColumnCount - 1);
}

FindingFilterProxyModel::FindingFilterProxyModel(QObject *parent) : QSortFilterProxyModel(parent)
{
    setFilterCaseSensitivity(Qt::CaseInsensitive);
    setFilterKeyColumn(-1);
    setSortCaseSensitivity(Qt::CaseInsensitive);
}

void FindingFilterProxyModel::setSeverityFilter(const QString &severity)
{
    m_severity = QStringList{QStringLiteral("CRITICAL"), QStringLiteral("HIGH"), QStringLiteral("MEDIUM"),
                             QStringLiteral("LOW"), QStringLiteral("INFO")}.contains(severity) ? severity : QString{};
    invalidateFilter();
}

void FindingFilterProxyModel::setConfidenceFilter(const QString &confidence)
{
    m_confidence = QStringList{QStringLiteral("HIGH"), QStringLiteral("MEDIUM"), QStringLiteral("LOW")}.contains(confidence)
        ? confidence : QString{};
    invalidateFilter();
}

void FindingFilterProxyModel::setModuleFilter(const QString &module)
{
    m_module = QStringList{QStringLiteral("dns"), QStringLiteral("http"), QStringLiteral("headers"),
                           QStringLiteral("tls")}.contains(module) ? module : QString{};
    invalidateFilter();
}

bool FindingFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    const auto *model = qobject_cast<const FindingTableModel *>(sourceModel());
    if (!model)
        return QSortFilterProxyModel::filterAcceptsRow(sourceRow, sourceParent);
    const auto finding = model->findingAt(sourceRow);
    if (!m_severity.isEmpty() && text(finding, QStringLiteral("severity")) != m_severity)
        return false;
    if (!m_confidence.isEmpty() && text(finding, QStringLiteral("confidence")) != m_confidence)
        return false;
    if (!m_module.isEmpty() && finding.value(QStringLiteral("module")).toString() != m_module)
        return false;
    return QSortFilterProxyModel::filterAcceptsRow(sourceRow, sourceParent);
}
