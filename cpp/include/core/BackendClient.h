#pragma once

#include <QJsonObject>
#include <QProcess>
#include <QSet>
#include <QObject>

class BackendClient final : public QObject {
    Q_OBJECT
public:
    explicit BackendClient(QObject *parent = nullptr);
    QString request(const QString &operation, const QJsonObject &payload = {});

signals:
    void responseReceived(const QString &id, const QJsonObject &response);
    void progressReceived(const QString &id, const QString &label, int step, int total);
    void backendError(const QString &message);

private slots:
    void readStandardOutput();
    void readStandardError();
    void processFinished(int exitCode, QProcess::ExitStatus status);

private:
    bool startBackend();
    void failPending(const QString &message);

    QProcess m_process;
    QByteArray m_stdoutBuffer;
    QSet<QString> m_pending;
};
