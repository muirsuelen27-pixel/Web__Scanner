#pragma once

#include "models/ScannerModels.h"

#include <QJsonObject>
#include <QWidget>

class QCheckBox;
class QComboBox;
class QDoubleSpinBox;
class QEvent;
class QLabel;
class QLineEdit;
class QProgressBar;
class QPushButton;
class QSpinBox;
class QTabWidget;
class QTableView;
class QTextBrowser;
class MetricCard;

class AnalysisPage final : public QWidget {
    Q_OBJECT
public:
    explicit AnalysisPage(QWidget *parent = nullptr);
    void setResult(const QJsonObject &result);
    void setGlobalFilter(const QString &text);
    void setProgress(const QString &label, int step, int total);
    void setBusy(bool busy);
    void setCompactMetrics(bool compact);
    void startScan();
    void setTarget(const QString &target);
    QJsonObject currentResult() const;
    void setSummary(const QString &summary);

signals:
    void scanRequested(const QJsonObject &request);
    void exportRequested(const QString &format, const QJsonObject &result);
    void summaryRequested(const QJsonObject &result);

protected:
    void changeEvent(QEvent *event) override;

private:
    void retranslateUi();
    void showFindingDetails(const QModelIndex &index);
    void updateMetrics();

    QLineEdit *m_target{};
    QLineEdit *m_filter{};
    QComboBox *m_severityFilter{};
    QComboBox *m_confidenceFilter{};
    QComboBox *m_moduleFilter{};
    QCheckBox *m_dns{};
    QCheckBox *m_http{};
    QCheckBox *m_headers{};
    QCheckBox *m_tls{};
    QPushButton *m_scanButton{};
    QPushButton *m_jsonButton{};
    QPushButton *m_pdfButton{};
    QPushButton *m_aiButton{};
    QProgressBar *m_progress{};
    QLabel *m_progressLabel{};
    QLabel *m_detail{};
    QTextBrowser *m_detailText{};
    QTableView *m_findingsView{};
    QTableView *m_technologyView{};
    QTabWidget *m_tabs{};
    FindingTableModel *m_findings{};
    FindingFilterProxyModel *m_findingProxy{};
    TechnologyTableModel *m_technologies{};
    QSortFilterProxyModel *m_technologyProxy{};
    QJsonObject m_result;
    QList<MetricCard *> m_metrics;
    QLabel *m_targetTitle{};
    QString m_summary;
};

class HistoryPage final : public QWidget {
    Q_OBJECT
public:
    explicit HistoryPage(QWidget *parent = nullptr);
    void setRecords(const QJsonArray &records);
    void setGlobalFilter(const QString &text);
    void selectFirst();
    void exportSelected(const QString &format);

signals:
    void refreshRequested();
    void selectedResult(const QJsonObject &result);
    void selectedRecord(const QJsonObject &record);
    void exportRequested(const QString &format, const QJsonObject &record);
    void deleteRequested(const QString &path);
    void clearRequested();

protected:
    void changeEvent(QEvent *event) override;

private:
    void retranslateUi();
    void showSelected(const QModelIndex &index);
    void emitSelectedResult();

    QLineEdit *m_filter{};
    QTableView *m_table{};
    QTextBrowser *m_detail{};
    QPushButton *m_jsonButton{};
    QPushButton *m_pdfButton{};
    QPushButton *m_deleteButton{};
    QPushButton *m_clearButton{};
    HistoryTableModel *m_model{};
    QSortFilterProxyModel *m_proxy{};
};

class KarenPage final : public QWidget {
    Q_OBJECT
public:
    explicit KarenPage(QWidget *parent = nullptr);
    void setResultContext(const QJsonObject &result);
    void appendAnswer(const QString &answer);
    void setBusy(bool busy);

signals:
    void chatRequested(const QJsonObject &request);

protected:
    void changeEvent(QEvent *event) override;

private:
    void retranslateUi();
    void sendMessage();
    void appendBubble(const QString &role, const QString &text, bool user);

    QTextBrowser *m_messages{};
    QLineEdit *m_input{};
    QPushButton *m_send{};
    QPushButton *m_clear{};
    QList<QPushButton *> m_suggestions;
    QJsonObject m_result;
    QJsonArray m_history;
    QJsonObject m_selectedRecord;
};

class SettingsPage final : public QWidget {
    Q_OBJECT
public:
    explicit SettingsPage(QWidget *parent = nullptr);
    void loadSettings(const QJsonObject &settings);
    void applySettings(const QJsonObject &settings);

signals:
    void settingsChanged(const QJsonObject &settings);
    void themeRequested(const QString &mode, const QString &accent);
    void languageRequested(const QString &language);
    void compactMetricsChanged(bool compact);

protected:
    void changeEvent(QEvent *event) override;

private:
    void retranslateUi();
    QJsonObject settings() const;

    QDoubleSpinBox *m_timeout{};
    QDoubleSpinBox *m_rate{};
    QSpinBox *m_redirects{};
    QLineEdit *m_model{};
    QComboBox *m_accent{};
    QComboBox *m_theme{};
    QComboBox *m_language{};
    QCheckBox *m_autoSummary{};
    QCheckBox *m_compact{};
    QPushButton *m_save{};
};
