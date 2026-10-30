#include "core/BackendClient.h"

#include "BuildConfig.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QDebug>
#include <QProcessEnvironment>
#include <QTimer>
#include <QUuid>

BackendClient::BackendClient(QObject *parent) : QObject(parent)
{
    m_process.setProcessChannelMode(QProcess::SeparateChannels);
    connect(&m_process, &QProcess::readyReadStandardOutput, this, &BackendClient::readStandardOutput);
    connect(&m_process, &QProcess::readyReadStandardError, this, &BackendClient::readStandardError);
    connect(&m_process, &QProcess::finished, this, &BackendClient::processFinished);
    connect(&m_process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart)
            failPending(tr("The Python backend could not be started. Check Python and the project path."));
    });
}

QString BackendClient::request(const QString &operation, const QJsonObject &payload)
{
    const QString id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    if (!startBackend()) {
        const QJsonObject failure{{QStringLiteral("ok"), false},
                                  {QStringLiteral("error"), tr("The Python backend is not running.")}};
        QTimer::singleShot(0, this, [this, id, failure] { emit responseReceived(id, failure); });
        return id;
    }
    QJsonObject message = payload;
    message.insert(QStringLiteral("id"), id);
    message.insert(QStringLiteral("operation"), operation);
    QByteArray line = QJsonDocument(message).toJson(QJsonDocument::Compact);
    line.append('\n');
    m_pending.insert(id);
    if (m_process.write(line) != line.size()) {
        m_pending.remove(id);
        const QJsonObject failure{{QStringLiteral("ok"), false},
                                  {QStringLiteral("error"), tr("Could not write a request to the Python backend.")}};
        QTimer::singleShot(0, this, [this, id, failure] { emit responseReceived(id, failure); });
    }
    return id;
}

bool BackendClient::startBackend()
{
    if (m_process.state() != QProcess::NotRunning)
        return true;
    const QString root = QDir::cleanPath(QStringLiteral(WEB_SCANNER_SOURCE_ROOT));
    const QString venvPython = QDir(root).filePath(QStringLiteral(".venv/Scripts/python.exe"));
    const QString python = qEnvironmentVariable("WEB_SCANNER_PYTHON",
                                                 QFileInfo::exists(venvPython) ? venvPython : QStringLiteral("python"));
    m_process.setWorkingDirectory(root);
    m_process.setProgram(python);
    m_process.setArguments({QStringLiteral("-m"), QStringLiteral("scanner.bridge")});
    auto environment = QProcessEnvironment::systemEnvironment();
    environment.insert(QStringLiteral("PYTHONUTF8"), QStringLiteral("1"));
    m_process.setProcessEnvironment(environment);
    m_process.start();
    return m_process.waitForStarted(5000);
}

void BackendClient::readStandardOutput()
{
    m_stdoutBuffer.append(m_process.readAllStandardOutput());
    while (true) {
        const qsizetype newline = m_stdoutBuffer.indexOf('\n');
        if (newline < 0)
            break;
        const QByteArray line = m_stdoutBuffer.left(newline).trimmed();
        m_stdoutBuffer.remove(0, newline + 1);
        if (line.isEmpty())
            continue;
        QJsonParseError parseError;
        const auto document = QJsonDocument::fromJson(line, &parseError);
        if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
            emit backendError(tr("The Python backend returned invalid JSON: %1").arg(parseError.errorString()));
            continue;
        }
        const auto response = document.object();
        const QString id = response.value(QStringLiteral("id")).toString();
        if (response.value(QStringLiteral("event")).toString() == QStringLiteral("progress")) {
            emit progressReceived(id,
                                  response.value(QStringLiteral("label")).toString(),
                                  response.value(QStringLiteral("step")).toInt(),
                                  response.value(QStringLiteral("total")).toInt());
        } else if (m_pending.remove(id)) {
            emit responseReceived(id, response);
        }
    }
}

void BackendClient::readStandardError()
{
    const QByteArray output = m_process.readAllStandardError().trimmed();
    if (!output.isEmpty())
        emit backendError(QString::fromLocal8Bit(output));
}

void BackendClient::processFinished(int exitCode, QProcess::ExitStatus status)
{
    if (!m_pending.isEmpty()) {
        const auto message = status == QProcess::CrashExit
            ? tr("The Python backend stopped unexpectedly.")
            : tr("The Python backend stopped with exit code %1.").arg(exitCode);
        failPending(message);
    }
}

void BackendClient::failPending(const QString &message)
{
    const auto pending = m_pending;
    m_pending.clear();
    for (const auto &id : pending)
        emit responseReceived(id, {{QStringLiteral("ok"), false}, {QStringLiteral("error"), message}});
    emit backendError(message);
}
