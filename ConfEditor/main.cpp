#include "confeditor.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    ConfEditor w;
    w.show();

    return a.exec();
}
