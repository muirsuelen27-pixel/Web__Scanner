#include "widgets/Sidebar.h"

#include <QEvent>
#include <QResizeEvent>
#include <QTimer>
#include <QLabel>
#include <QParallelAnimationGroup>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QStyle>
#include <QIcon>
#include <QPixmap>
#include <QVBoxLayout>

Sidebar::Sidebar(QWidget *parent) : QFrame(parent)
{
    setObjectName(QStringLiteral("sidebar"));
    setMinimumWidth(72);
    setMaximumWidth(260);
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 26, 16, 20);
    layout->setSpacing(9);

    m_brand = new QLabel(this);
    m_brand->setObjectName(QStringLiteral("brand"));
    m_brand->setPixmap(QPixmap(QStringLiteral(":/assets/logo.svg")).scaled(48, 48, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    layout->addWidget(m_brand, 0, Qt::AlignHCenter);
    m_caption = new QLabel(this);
    m_caption->setObjectName(QStringLiteral("sidebarCaption"));
    m_caption->setAlignment(Qt::AlignCenter);
    layout->addWidget(m_caption);
    layout->addSpacing(22);

    const QStringList icons{
        QStringLiteral(":/assets/icons/analysis.svg"),
        QStringLiteral(":/assets/icons/history.svg"),
        QStringLiteral(":/assets/icons/karen.svg"),
        QStringLiteral(":/assets/icons/settings.svg"),
    };
    for (int index = 0; index < 4; ++index) {
        auto *button = new QPushButton(this);
        button->setObjectName(QStringLiteral("navButton"));
        button->setCheckable(true);
        button->setProperty("pageIndex", index);
        button->setProperty("collapsed", false);
        button->setIcon(QIcon(icons.at(index)));
        button->setIconSize(QSize(20, 20));
        button->setMinimumHeight(46);
        button->setAccessibleName(QStringList{tr("New analysis"), tr("History and reports"), tr("Karen assistant"), tr("Settings")}.at(index));
        connect(button, &QPushButton::clicked, this, [this, index] {
            setCurrentPage(index);
            emit pageRequested(index);
        });
        m_buttons.append(button);
        layout->addWidget(button);
    }
    layout->addStretch(1);
    m_indicator = new QFrame(this);
    m_indicator->setObjectName(QStringLiteral("sidebarIndicator"));
    m_indicator->setAttribute(Qt::WA_TransparentForMouseEvents);
    setCurrentPage(0);
    retranslateUi();
    QTimer::singleShot(0, this, [this] { moveIndicator(m_currentPage, false); });
}

void Sidebar::setCurrentPage(int index)
{
    if (index < 0 || index >= m_buttons.size())
        return;
    m_currentPage = index;
    for (int buttonIndex = 0; buttonIndex < m_buttons.size(); ++buttonIndex)
        m_buttons.at(buttonIndex)->setChecked(buttonIndex == index);
    moveIndicator(index, true);
}

void Sidebar::setCollapsed(bool collapsed)
{
    if (m_collapsed == collapsed)
        return;
    m_collapsed = collapsed;
    setMaximumWidth(collapsed ? 82 : 260);
    setMinimumWidth(collapsed ? 72 : 230);
    m_brand->setVisible(!collapsed);
    m_caption->setVisible(!collapsed);
    for (auto *button : m_buttons) {
        const int index = button->property("pageIndex").toInt();
        button->setText(collapsed ? QString{} :
            QStringList{tr("New analysis"), tr("History and reports"), tr("Karen"), tr("Settings")}.at(index));
        button->setProperty("collapsed", collapsed);
        button->style()->unpolish(button);
        button->style()->polish(button);
    }
}

bool Sidebar::isCollapsed() const
{
    return m_collapsed;
}

void Sidebar::resizeEvent(QResizeEvent *event)
{
    QFrame::resizeEvent(event);
    moveIndicator(m_currentPage, false);
}

void Sidebar::moveIndicator(int index, bool animated)
{
    if (index < 0 || index >= m_buttons.size())
        return;
    const auto *button = m_buttons.at(index);
    const QRect target(8, button->y(), 3, button->height());
    if (!animated || m_indicator->geometry().isNull()) {
        m_indicator->setGeometry(target);
        return;
    }
    auto *animation = new QPropertyAnimation(m_indicator, "geometry", this);
    animation->setDuration(230);
    animation->setStartValue(m_indicator->geometry());
    animation->setEndValue(target);
    animation->setEasingCurve(QEasingCurve::OutCubic);
    animation->start(QAbstractAnimation::DeleteWhenStopped);
}

void Sidebar::changeEvent(QEvent *event)
{
    if (event->type() == QEvent::LanguageChange)
        retranslateUi();
    QFrame::changeEvent(event);
}

void Sidebar::retranslateUi()
{
    const QStringList labels{tr("New analysis"), tr("History and reports"), tr("Karen"), tr("Settings")};
    m_caption->setText(m_collapsed ? QString{} : tr("SECURITY INTELLIGENCE"));
    for (int index = 0; index < m_buttons.size(); ++index) {
        m_buttons.at(index)->setText(m_collapsed ? QString{} : labels.at(index));
        m_buttons.at(index)->setAccessibleName(labels.at(index));
    }
    moveIndicator(m_currentPage, false);
}
