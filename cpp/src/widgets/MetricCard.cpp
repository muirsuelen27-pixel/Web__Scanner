#include "widgets/MetricCard.h"

#include <QGraphicsOpacityEffect>
#include <QAbstractAnimation>
#include <QEasingCurve>
#include <QLabel>
#include <QLayout>
#include <QPropertyAnimation>
#include <QStyle>
#include <QTimer>
#include <QVBoxLayout>

MetricCard::MetricCard(const QString &title, const QString &accent, QWidget *parent)
    : QFrame(parent), m_title(new QLabel(title, this)), m_value(new QLabel(QStringLiteral("—"), this))
{
    setObjectName(QStringLiteral("metricCard"));
    setAccessibleName(title);
    m_title->setObjectName(QStringLiteral("metricTitle"));
    m_value->setObjectName(QStringLiteral("metricValue"));
    m_value->setProperty("metricAccent", accent);
    m_value->setProperty("compact", false);
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 13, 16, 13);
    layout->addWidget(m_title);
    layout->addWidget(m_value);
}

void MetricCard::setTitle(const QString &title)
{
    m_title->setText(title);
    setAccessibleName(title);
}

void MetricCard::setValue(const QString &value)
{
    m_value->setText(value);
}

void MetricCard::setCompact(bool compact)
{
    layout()->setContentsMargins(12, compact ? 7 : 13, 12, compact ? 7 : 13);
    m_value->setProperty("compact", compact);
    m_value->style()->unpolish(m_value);
    m_value->style()->polish(m_value);
}

void MetricCard::animateIn(int delayMs)
{
    auto *effect = new QGraphicsOpacityEffect(this);
    setGraphicsEffect(effect);
    effect->setOpacity(0.0);
    QTimer::singleShot(delayMs, this, [this, effect] {
        auto *animation = new QPropertyAnimation(effect, "opacity", this);
        animation->setDuration(260);
        animation->setStartValue(0.0);
        animation->setEndValue(1.0);
        animation->setEasingCurve(QEasingCurve::OutCubic);
        animation->start(QAbstractAnimation::DeleteWhenStopped);
    });
}
