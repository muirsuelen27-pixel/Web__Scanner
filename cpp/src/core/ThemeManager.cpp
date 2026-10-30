#include "core/ThemeManager.h"

#include <QFile>
#include <QGuiApplication>
#include <QStyleHints>
#include <QWidget>

ThemeManager::ThemeManager(QObject *parent) : QObject(parent)
{
    connect(QGuiApplication::styleHints(), &QStyleHints::colorSchemeChanged, this, [this] {
        if (m_mode == QStringLiteral("auto"))
            emit themeChanged();
    });
}

ThemeManager *ThemeManager::instance()
{
    static ThemeManager manager;
    return &manager;
}

QString ThemeManager::accent() const { return m_accent; }
QString ThemeManager::mode() const { return m_mode; }

void ThemeManager::setAccent(const QString &accent)
{
    if (accent == QStringLiteral("cyan") || accent == QStringLiteral("indigo") || accent == QStringLiteral("emerald")) {
        if (m_accent == accent) return;
        m_accent = accent;
        emit themeChanged();
    }
}

void ThemeManager::setMode(const QString &mode)
{
    if (mode == QStringLiteral("dark") || mode == QStringLiteral("light") || mode == QStringLiteral("auto")) {
        if (m_mode == mode) return;
        m_mode = mode;
        emit themeChanged();
    }
}

QString ThemeManager::resolvedMode() const
{
    if (m_mode == QStringLiteral("auto"))
        return QGuiApplication::styleHints()->colorScheme() == Qt::ColorScheme::Dark
            ? QStringLiteral("dark") : QStringLiteral("light");
    return m_mode;
}

void ThemeManager::apply(QWidget *widget)
{
    QFile base(QStringLiteral(":/themes/%1.qss").arg(resolvedMode()));
    QFile accent(QStringLiteral(":/themes/accent-%1.qss").arg(m_accent));
    if (!base.open(QIODevice::ReadOnly) || !accent.open(QIODevice::ReadOnly))
        return;
    widget->setStyleSheet(QString::fromUtf8(base.readAll()) + QLatin1Char('\n')
                          + QString::fromUtf8(accent.readAll()));
}
