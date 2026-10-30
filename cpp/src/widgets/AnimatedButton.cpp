#include "widgets/AnimatedButton.h"

#include <QMouseEvent>
#include <QAbstractAnimation>
#include <QEasingCurve>
#include <QPainter>
#include <QPainterPath>
#include <QPropertyAnimation>

AnimatedButton::AnimatedButton(const QString &text, QWidget *parent) : QPushButton(text, parent) {}

qreal AnimatedButton::rippleProgress() const { return m_rippleProgress; }

void AnimatedButton::setRippleProgress(qreal progress)
{
    m_rippleProgress = progress;
    update();
}

void AnimatedButton::mousePressEvent(QMouseEvent *event)
{
    m_rippleCenter = event->position().toPoint();
    auto *animation = new QPropertyAnimation(this, "rippleProgress", this);
    animation->setDuration(430);
    animation->setStartValue(0.05);
    animation->setEndValue(1.0);
    animation->setEasingCurve(QEasingCurve::OutCubic);
    animation->start(QAbstractAnimation::DeleteWhenStopped);
    QPushButton::mousePressEvent(event);
}

void AnimatedButton::paintEvent(QPaintEvent *event)
{
    QPushButton::paintEvent(event);
    if (m_rippleProgress <= 0.0)
        return;
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    QPainterPath clip;
    clip.addRoundedRect(rect(), 9, 9);
    painter.setClipPath(clip);
    const qreal radius = qMax(width(), height()) * m_rippleProgress;
    QColor color = palette().color(QPalette::ButtonText);
    color.setAlphaF(qMax(0.0, 0.18 * (1.0 - m_rippleProgress)));
    painter.setBrush(color);
    painter.setPen(Qt::NoPen);
    painter.drawEllipse(m_rippleCenter, radius, radius);
}
