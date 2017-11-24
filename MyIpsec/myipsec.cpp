#include "myipsec.h"
#include "ui_myipsec.h"
#include <QDebug>

MyIpsec::MyIpsec(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MyIpsec),
    editor(new ConfEditor(this)),
    started(false)
{
    ui->setupUi(this);
    this->setFixedSize(this->size());

    initSignals();
}

MyIpsec::~MyIpsec()
{
    delete ui;
}

void MyIpsec::initSignals() {
    connect(editor.get(), &ConfEditor::saved, this, &MyIpsec::onConfigChanged);
}

void MyIpsec::on_startButton_clicked() {
    qDebug() << "start button clicked";

    if (!started) {
        emit startAction();
    } else {
        emit stopAction();
    }
}

void MyIpsec::on_restartButton_clicked() {
    qDebug() << "restart button clicked";
    on_startButton_clicked();
    on_startButton_clicked();
}

void MyIpsec::on_configButton_clicked() {
    qDebug() << "config button clicked";
    editor->show();
}

void MyIpsec::on_logButton_clicked() {
    qDebug() << "log button clicked";
}

void MyIpsec::onConfigChanged(QString config) {
    qDebug() << "config file changed";
}
