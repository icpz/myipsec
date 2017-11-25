#ifndef LOGDIALOG_H
#define LOGDIALOG_H

#include <QDialog>
#include <QFileSystemWatcher>
#include <QFile>
#include <QTextStream>
#include <memory>

namespace Ui {
class LogDialog;
}

class LogDialog : public QDialog
{
    Q_OBJECT

public:
    explicit LogDialog(QWidget *parent = 0);
    ~LogDialog();

    void setupLogFile(const QString &name);
    void onFileChanged(const QString &path);
    void addAlert(const QString &msg);

private:
    Ui::LogDialog *ui;
    std::unique_ptr<QFileSystemWatcher> fs;
    std::unique_ptr<QFile> logFile;
    std::unique_ptr<QTextStream> qts;
};

#endif // LOGDIALOG_H
