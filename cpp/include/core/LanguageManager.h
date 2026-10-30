#pragma once

#include <QTranslator>
#include <QObject>

class LanguageManager final : public QObject {
    Q_OBJECT
public:
    static LanguageManager *instance();
    QString language() const;
    bool setLanguage(const QString &language);

signals:
    void languageChanged(const QString &language);

private:
    explicit LanguageManager(QObject *parent = nullptr);
    QTranslator m_translator;
    QString m_language{QStringLiteral("en")};
};
