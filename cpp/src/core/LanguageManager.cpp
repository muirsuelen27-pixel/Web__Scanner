#include "core/LanguageManager.h"

#include <QCoreApplication>
#include <QDir>

LanguageManager::LanguageManager(QObject *parent) : QObject(parent) {}

LanguageManager *LanguageManager::instance()
{
    static LanguageManager manager;
    return &manager;
}

QString LanguageManager::language() const
{
    return m_language;
}

bool LanguageManager::setLanguage(const QString &language)
{
    if (language == m_language)
        return true;
    if (language != QStringLiteral("en") && language != QStringLiteral("es") && language != QStringLiteral("fr"))
        return false;

    QCoreApplication::removeTranslator(&m_translator);
    if (language != QStringLiteral("en")) {
        const QString resource = QStringLiteral(":/i18n/webscanner_%1.qm").arg(language);
        if (!m_translator.load(resource))
            return false;
        QCoreApplication::installTranslator(&m_translator);
    }
    m_language = language;
    emit languageChanged(m_language);
    return true;
}
