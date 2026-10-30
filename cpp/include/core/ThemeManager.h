#pragma once

#include <QObject>

class QWidget;

class ThemeManager final : public QObject {
    Q_OBJECT
public:
    static ThemeManager *instance();
    QString accent() const;
    QString mode() const;
    void setAccent(const QString &accent);
    void setMode(const QString &mode);
    void apply(QWidget *widget);

signals:
    void themeChanged();

private:
    explicit ThemeManager(QObject *parent = nullptr);
    QString resolvedMode() const;
    QString m_accent{QStringLiteral("cyan")};
    QString m_mode{QStringLiteral("dark")};
};
