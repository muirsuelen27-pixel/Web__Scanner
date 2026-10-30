#pragma once

#include <QAbstractTableModel>
#include <QJsonArray>
#include <QJsonObject>
#include <QStringList>
#include <QSortFilterProxyModel>

class FindingTableModel final : public QAbstractTableModel {
    Q_OBJECT
public:
    enum Column { Severity, Title, Confidence, Status, Module, ColumnCount };

    explicit FindingTableModel(QObject *parent = nullptr);
    int rowCount(const QModelIndex &parent = {}) const override;
    int columnCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    void setFindings(const QJsonArray &findings, const QJsonArray &modules = {});
    QJsonObject findingAt(int row) const;
    void retranslateHeaders();

private:
    QJsonArray m_findings;
};

class TechnologyTableModel final : public QAbstractTableModel {
    Q_OBJECT
public:
    enum Column { Name, Category, Evidence, Confidence, ColumnCount };

    explicit TechnologyTableModel(QObject *parent = nullptr);
    int rowCount(const QModelIndex &parent = {}) const override;
    int columnCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    void setTechnologies(const QJsonArray &technologies);
    void retranslateHeaders();

private:
    QJsonArray m_technologies;
};

class HistoryTableModel final : public QAbstractTableModel {
    Q_OBJECT
public:
    enum Column { Started, Target, Risk, FindingCount, ColumnCount };

    explicit HistoryTableModel(QObject *parent = nullptr);
    int rowCount(const QModelIndex &parent = {}) const override;
    int columnCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    void setRecords(const QJsonArray &records);
    QJsonObject recordAt(int row) const;
    void retranslateHeaders();

private:
    QJsonArray m_records;
};

class FindingFilterProxyModel final : public QSortFilterProxyModel {
    Q_OBJECT
public:
    explicit FindingFilterProxyModel(QObject *parent = nullptr);
    void setSeverityFilter(const QString &severity);
    void setConfidenceFilter(const QString &confidence);
    void setModuleFilter(const QString &module);

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override;

private:
    QString m_severity;
    QString m_confidence;
    QString m_module;
};
