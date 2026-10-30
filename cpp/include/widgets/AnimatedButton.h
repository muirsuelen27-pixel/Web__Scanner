#pragma once

#include <QPushButton>

class QPropertyAnimation;

class AnimatedButton final : public QPushButton {
    Q_OBJECT
    Q_PROPERTY(qreal rippleProgress READ rippleProgress WRITE setRippleProgress)
public:
    explicit AnimatedButton(const QString &text = {}, QWidget *parent = nullptr);
    qreal rippleProgress() const;
    void setRippleProgress(qreal progress);

protected:
    void mousePressEvent(QMouseEvent *event) override;
    void paintEvent(QPaintEvent *event) override;

private:
    qreal m_rippleProgress{};
    QPoint m_rippleCenter;
};
