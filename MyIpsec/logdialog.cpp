#include "logdialog.h"
#include "ui_logdialog.h"

LogDialog::LogDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::LogDialog)
{
    ui->setupUi(this);

    setFixedSize(size());
}

LogDialog::~LogDialog()
{
    delete ui;
}
