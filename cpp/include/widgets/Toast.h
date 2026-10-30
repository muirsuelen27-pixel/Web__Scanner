#pragma once

#include <QFrame>

class QLabel;

class Toast final : public QFrame {
    Q_OBJECT
public:
    explicit Toast(QWidget *parent = nullptr);
    void showMessage(const QString &message, bool isError = false);

private:
    QLabel *m_label{};
};
