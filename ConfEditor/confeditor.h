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

private:
    void onAddButtonClicked();
    void newConfFile();
    void openConfFile();
    void saveToConfFile();

    void initSignals();
    bool checkInput();

    Ui::ConfEditor *ui;
    bool fileChanged;
};

#endif // CONFEDITOR_H
