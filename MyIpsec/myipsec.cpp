#include "myipsec.h"
#include "ui_myipsec.h"
#include <QDebug>
#include <QSettings>

MyIpsec::MyIpsec(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MyIpsec),
    editor(new ConfEditor(this)),
    started(false)
{
    ui->setupUi(this);
    this->setFixedSize(this->size());
    ui->startButton->setText(tr("Start"));
    ui->statusLabel->setText(tr("OFF"));
    ui->restartButton->setEnabled(false);
    ui->logButton->setEnabled(false);

    initSignals();
    process.setProgram("bin/myipsec");
}

MyIpsec::~MyIpsec()
{
    delete ui;
    if (started) stopFirewall();
}

void MyIpsec::initSignals() {
    connect(editor.get(), &ConfEditor::saved, this, &MyIpsec::onConfigChanged);
    connect(this, &MyIpsec::alert, [this](QString msg, bool append) {
        if (append) {
            msg = QString("%1, %2").arg(ui->alertLabel->text(), msg);
        }
        ui->alertLabel->setText(msg);
    });
    connect(&process, static_cast<void(QProcess::*)(int, QProcess::ExitStatus)>(&QProcess::finished),
    [this](int code, QProcess::ExitStatus status) {
        QProcess::execute("bin/iptables_setup.sh reset");
        started = false;
        ui->startButton->setText(tr("Start"));
        ui->statusLabel->setText(tr("OFF"));
        ui->restartButton->setEnabled(false);
        ui->logButton->setEnabled(false);
        if (status == QProcess::CrashExit) {
            emit alert(tr("myipsec crashed! Please do check"));
            return;
        }
        qDebug() << "myipsec exits with code: " << code;
    });
    connect(&process, &QProcess::started, [this]() {
        started = true;
        ui->startButton->setText(tr("Stop"));
        ui->statusLabel->setText(tr("ON"));
        ui->restartButton->setEnabled(true);
        ui->logButton->setEnabled(true);
    });
}

void MyIpsec::on_startButton_clicked() {
    qDebug() << "start button clicked";
    if (process.state() == QProcess::Starting) return;
    ui->alertLabel->setText(tr(""));
    if (!started && startFirewall()) {
        ui->statusLabel->setText(tr("..."));
    } else if (started && stopFirewall()) {
        started = false;
        ui->startButton->setText(tr("Start"));
        ui->statusLabel->setText(tr("OFF"));
        ui->restartButton->setEnabled(false);
        ui->logButton->setEnabled(false);
    } else {
        emit alert(tr("Failed to setup firewall!"), true);
    }
}

void MyIpsec::on_restartButton_clicked() {
    qDebug() << "restart button clicked";
    on_startButton_clicked();
    on_startButton_clicked();
}

static QString __loadConfigText() {
    QSettings settings("IS.SJTU", "MyIpsec");
    settings.beginGroup("gui");
    QString result = settings.value("config", QVariant(QString())).value<QString>();
    settings.endGroup();
    return result;
}

static void __storeConfigText(QString config) {
    QSettings settings("IS.SJTU", "MyIpsec");
    settings.beginGroup("gui");
    settings.setValue("config", config);
    settings.endGroup();
}

void MyIpsec::on_configButton_clicked() {
    qDebug() << "config button clicked";
    editor->load(__loadConfigText());
    editor->show();
}

void MyIpsec::on_logButton_clicked() {
    qDebug() << "log button clicked";
}

void MyIpsec::onConfigChanged(QString config) {
    qDebug() << "config file changed";
    __storeConfigText(config);
}

bool MyIpsec::startFirewall() {
    if (!workDir.isValid()) {
        alert(tr("Cannot write temp dirs!"));
        return false;
    }
    qDebug() << "tmp dir: " << workDir.path();
    QString path = workDir.filePath("config.txt");
    QFile file(path);
    file.open(QIODevice::WriteOnly | QIODevice::Text);
    QTextStream qss(&file);
    qss << __loadConfigText();
    file.close();

    QStringList args;
    args << "-c" << path;
    process.setArguments(args);

    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert("GLOG_log_dir", workDir.path());
    env.insert("GLOG_v", "2");
    process.setProcessEnvironment(env);

    QProcess::execute("bin/iptables_setup.sh setup");
    process.start();

    return true;
}

bool MyIpsec::stopFirewall() {
    if (process.state() != QProcess::Running) return true;
    process.terminate();
    if (!process.waitForFinished()) {
        qDebug() << "exit timeout, killing";
        process.kill();
    }
    QProcess::execute("bin/iptables_setup.sh reset");
    return true;
}
