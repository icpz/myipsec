#include "logdialog.h"
#include "ui_logdialog.h"
#include <QDebug>

LogDialog::LogDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::LogDialog)
{
    ui->setupUi(this);

    setFixedSize(size());
    connect(ui->logView, &QTextBrowser::textChanged,
            [this]() {
        QTextCursor c = ui->logView->textCursor();
        c.movePosition(QTextCursor::End);
        ui->logView->setTextCursor(c);
    });
}

LogDialog::~LogDialog()
{
    delete ui;
}

void LogDialog::setupLogFile(const QString &name) {
    if (fs) fs->disconnect();
    fs.reset(new QFileSystemWatcher);
    logFile.reset(new QFile(name));
    ui->logView->setText("");
    connect(fs.get(), &QFileSystemWatcher::fileChanged,
            this, &LogDialog::onFileChanged);
    if (logFile->open(QIODevice::ReadOnly | QIODevice::Text)) {
        qts.reset(new QTextStream(logFile.get()));
        ui->logView->setText(qts->readAll());
    }
    fs->addPath(name);
    qDebug() << name << " watched";
}

void LogDialog::addAlert(const QString &msg) {
    ui->alertView->append(msg);
}

void LogDialog::onFileChanged(const QString &path) {
    if (!logFile->exists()) return;
    if (!logFile->isOpen()) {
        logFile->setFileName(path);
        if (!logFile->open(QIODevice::ReadOnly | QIODevice::Text)) {
            qDebug() << "logging file error: " << path;
            return;
        }
        qts.reset(new QTextStream(logFile.get()));
        ui->logView->setText(qts->readAll());
        return;
    }
    auto view = ui->logView;
    view->moveCursor(QTextCursor::End);
    view->insertPlainText(qts->readAll());
}
