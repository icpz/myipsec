#ifndef CONFEDITOR_H
#define CONFEDITOR_H

#include <QMainWindow>

namespace Ui {
class ConfEditor;
}

class ConfEditor : public QMainWindow
{
    Q_OBJECT

public:
    explicit ConfEditor(QWidget *parent = 0);
    ~ConfEditor();

    void load(QString config);

signals:
    void configChanged();
    void saved(QString config);

private:
    void onAddButtonClicked();
    void onSaveButtonClicked();

    void initSignals();
    bool checkInput();

    Ui::ConfEditor *ui;
    bool fileChanged;
};

#endif // CONFEDITOR_H
