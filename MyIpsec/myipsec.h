#ifndef MYIPSEC_H
#define MYIPSEC_H

#include <QMainWindow>
#include <confeditor.h>
#include <memory>

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
    void startAction();
    void stopAction();
    void alert(QString msg);

private slots:
    void on_configButton_clicked();
    void on_startButton_clicked();
    void on_restartButton_clicked();
    void on_logButton_clicked();
    void onConfigChanged(QString config);

private:
    void initSignals();

    Ui::MyIpsec *ui;
    std::unique_ptr<ConfEditor> editor;
    bool started;
};

#endif // MYIPSEC_H
