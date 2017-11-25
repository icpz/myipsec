#include "myipsec.h"
#include <QApplication>
#include <QString>
#include <QMessageBox>
#include <memory>
#include <unistd.h>

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
    w.reset(new MyIpsec);
    w->show();

    return a.exec();
}
