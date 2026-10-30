#pragma once

#include <QMainWindow>
#include <QHash>
#include <QJsonObject>

class BackendClient;
class HistoryPage;
class KarenPage;
class AnalysisPage;
class SettingsPage;
class Sidebar;
class Toast;
class QLabel;
class QLineEdit;
class QStackedWidget;
class QResizeEvent;
class QEvent;

class MainWindow final : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(const QString &target = {}, QWidget *parent = nullptr);

protected:
    void changeEvent(QEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;

private:
    void buildUi();
    void connectUi();
    void showPage(int index);
    void retranslateUi();
    void loadSettings();
    void saveSettings(const QJsonObject &settings);
    void requestHistory();
    void requestExport(const QString &format, const QJsonObject &record);
    void beginRequest(const QString &operation, const QJsonObject &payload = {});
    void handleResponse(const QString &id, const QJsonObject &response);
    void updateAiStatus(const QJsonObject &response);
    void startScan();
    void refreshHistory();
    void exportCurrent();

    BackendClient *m_backend{};
    Sidebar *m_sidebar{};
    QStackedWidget *m_pages{};
    AnalysisPage *m_analysis{};
    HistoryPage *m_history{};
    KarenPage *m_karen{};
    SettingsPage *m_settingsPage{};
    QLineEdit *m_globalSearch{};
    QLabel *m_pageTitle{};
    QLabel *m_pageSubtitle{};
    QLabel *m_aiStatus{};
    Toast *m_toast{};
    QJsonObject m_settings;
    QJsonObject m_currentResult;
    QString m_currentHistoryPath;
    QHash<QString, QString> m_requestKinds;
    bool m_aiAvailable{};
    bool m_ollamaAvailable{};
};
