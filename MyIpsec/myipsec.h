#ifndef MYIPSEC_H
#define MYIPSEC_H

#include <QMainWindow>
#include <confeditor.h>
#include <memory>
#include <QTemporaryDir>
#include <QProcess>

namespace Ui {
class MyIpsec;
}

class MyIpsec : public QMainWindow
{
    Q_OBJECT

public:
    explicit MyIpsec(QWidget *parent = 0);
    ~MyIpsec();

signals:
    void alert(QString msg, bool append = false);

private slots:
    void on_configButton_clicked();
    void on_startButton_clicked();
    void on_restartButton_clicked();
    void on_logButton_clicked();
    void onConfigChanged(QString config);

private:
    void initSignals();
    bool startFirewall();
    bool stopFirewall();

    Ui::MyIpsec *ui;
    std::unique_ptr<ConfEditor> editor;
    bool started;
    QTemporaryDir workDir;
    QProcess process;
};

#endif // MYIPSEC_H
