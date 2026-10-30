#pragma once

#include <QFrame>

class QPushButton;
class QResizeEvent;

class Sidebar final : public QFrame {
    Q_OBJECT
public:
    explicit Sidebar(QWidget *parent = nullptr);
    void setCurrentPage(int index);
    void setCollapsed(bool collapsed);
    bool isCollapsed() const;

signals:
    void pageRequested(int index);

protected:
    void changeEvent(QEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;

private:
    void retranslateUi();
    void moveIndicator(int index, bool animated);

    QList<QPushButton *> m_buttons;
    QFrame *m_indicator{};
    QLabel *m_brand{};
    QLabel *m_caption{};
    int m_currentPage{};
    bool m_collapsed{};
};
