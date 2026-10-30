#include "widgets/Toast.h"

#include <QGraphicsOpacityEffect>
#include <QAbstractAnimation>
#include <QEasingCurve>
#include <QLabel>
#include <QPropertyAnimation>
#include <QStyle>
#include <QTimer>
#include <QVBoxLayout>

Toast::Toast(QWidget *parent) : QFrame(parent), m_label(new QLabel(this))
{
    setObjectName(QStringLiteral("toast"));
    setAttribute(Qt::WA_TransparentForMouseEvents);
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 11, 16, 11);
    layout->addWidget(m_label);
    hide();
}

void Toast::showMessage(const QString &message, bool isError)
{
    m_label->setText(message);
    setProperty("error", isError);
    style()->unpolish(this);
    style()->polish(this);
    adjustSize();
    if (parentWidget())
        move(parentWidget()->width() - width() - 28, parentWidget()->height() - height() - 24);
    auto *effect = qobject_cast<QGraphicsOpacityEffect *>(graphicsEffect());
    if (!effect) {
        effect = new QGraphicsOpacityEffect(this);
        setGraphicsEffect(effect);
    }
    effect->setOpacity(0.0);
    show();
    raise();
    auto *animation = new QPropertyAnimation(effect, "opacity", this);
    animation->setDuration(190);
    animation->setStartValue(0.0);
    animation->setEndValue(1.0);
    animation->setEasingCurve(QEasingCurve::OutCubic);
    animation->start(QAbstractAnimation::DeleteWhenStopped);
    QTimer::singleShot(3500, this, [this, effect] {
        auto *fade = new QPropertyAnimation(effect, "opacity", this);
        fade->setDuration(180);
        fade->setStartValue(1.0);
        fade->setEndValue(0.0);
        connect(fade, &QPropertyAnimation::finished, this, &QWidget::hide);
        fade->start(QAbstractAnimation::DeleteWhenStopped);
    });
}
