#include "myipsec.h"
#include <QApplication>
#include <QString>
#include <QLockFile>
#include <QDir>
#include <QMessageBox>
#include <memory>
#include <unistd.h>

QLockFile lockFile(QDir::tempPath() + "MyIpsec.lock");

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    std::unique_ptr<MyIpsec> w;
    if (getuid() != 0) {
        QMessageBox::warning(nullptr, "Error!",
                             "MyIpsec needs root permission",
                             QMessageBox::Ok);
        return 0;
    }

    if (!lockFile.tryLock(300)) {
        QMessageBox::warning(nullptr, "Multi-instance detected",
                             "You probably already have this app running",
                             QMessageBox::Ok);
        return 0;
    }

    w.reset(new MyIpsec);
    w->show();

    return a.exec();
}
