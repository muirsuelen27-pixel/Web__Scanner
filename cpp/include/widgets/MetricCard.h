#pragma once

#include <QFrame>
#include <QString>

class QLabel;

class MetricCard final : public QFrame {
    Q_OBJECT
public:
    explicit MetricCard(const QString &title, const QString &accent, QWidget *parent = nullptr);
    void setTitle(const QString &title);
    void setValue(const QString &value);
    void setCompact(bool compact);
    void animateIn(int delayMs);

private:
    QLabel *m_title{};
    QLabel *m_value{};
};
