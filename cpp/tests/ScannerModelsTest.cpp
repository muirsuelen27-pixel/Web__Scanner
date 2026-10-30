#include "models/ScannerModels.h"

#include <QJsonObject>
#include <QTest>

class ScannerModelsTest final : public QObject {
    Q_OBJECT
private slots:
    void findingModelExposesRowsAndColumns()
    {
        FindingTableModel model;
        model.setFindings({QJsonObject{{QStringLiteral("severity"), QStringLiteral("HIGH")},
                                       {QStringLiteral("title"), QStringLiteral("Observed header")},
                                       {QStringLiteral("confidence"), QStringLiteral("HIGH")},
                                       {QStringLiteral("status"), QStringLiteral("Observed")}}});
        QCOMPARE(model.rowCount(), 1);
        QCOMPARE(model.columnCount(), FindingTableModel::ColumnCount);
        QCOMPARE(model.data(model.index(0, FindingTableModel::Title), Qt::DisplayRole).toString(),
                 QStringLiteral("Observed header"));
    }
};

QTEST_MAIN(ScannerModelsTest)
#include "ScannerModelsTest.moc"
