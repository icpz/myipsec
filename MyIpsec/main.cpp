#include "myipsec.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MyIpsec w;
    w.show();

    return a.exec();
}
