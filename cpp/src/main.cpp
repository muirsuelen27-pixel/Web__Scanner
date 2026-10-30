#include "ui/MainWindow.h"

#include <QApplication>
#include <QGuiApplication>
#include <QIcon>
#include <QCommandLineParser>
#include <QSettings>
#include <Qt>

int main(int argc, char *argv[])
{
    QGuiApplication::setHighDpiScaleFactorRoundingPolicy(Qt::HighDpiScaleFactorRoundingPolicy::PassThrough);
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("WebScanner"));
    QCoreApplication::setApplicationName(QStringLiteral("WebScannerDesktop"));
    app.setWindowIcon(QIcon(QStringLiteral(":/assets/logo.svg")));
    QCommandLineParser parser;
    parser.addHelpOption();
    QCommandLineOption targetOption(QStringList{QStringLiteral("target")},
                                    QStringLiteral("Pre-fill an authorized scan target."),
                                    QStringLiteral("url"));
    parser.addOption(targetOption);
    parser.process(app);
    MainWindow window(parser.value(targetOption));
    window.show();
    return app.exec();
}
