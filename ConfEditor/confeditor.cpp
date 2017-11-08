#include "confeditor.h"
#include "ui_confeditor.h"
#include <string>
#include <stdint.h>
#include <QTextStream>
#include <QMessageBox>
#include <QFileDialog>
#include <QDebug>

ConfEditor::ConfEditor(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::ConfEditor)
{
    ui->setupUi(this);
    delete ui->mainToolBar;

    this->setFixedSize(this->size());
    fileChanged = false;
    initSignals();
}

ConfEditor::~ConfEditor()
{
    delete ui;
}

void ConfEditor::onAddButtonClicked() {
    if (!checkInput()) return;
    QString line;
    QTextStream oss(&line);
    oss << ui->ipEdit->text() << " ";
    oss << ui->protoCombo->currentText() << " ";
    auto action = ui->actionCombo->currentText();
    oss << action;
    if (action == tr("crypt")) {
        oss << " ";
        oss << ui->keyEdit->text() << " ";
        oss << ui->formatCombo->currentText() << " ";
        oss << ui->methodCombo->currentText();
    }
    ui->confTextEdit->appendPlainText(line);
    fileChanged = true;
}

void ConfEditor::newConfFile() {
    if (fileChanged) {
        auto reply = QMessageBox::question(this, tr("New File"), tr("You've made changes, press OK to save"),
                              QMessageBox::Ok | QMessageBox::Cancel, QMessageBox::Ok);
        if (reply == QMessageBox::Ok) {
            saveToConfFile();
        }
    }
    ui->confTextEdit->clear();
    fileChanged = false;
}

void ConfEditor::openConfFile() {
    if (fileChanged) {
        auto reply = QMessageBox::question(this, tr("New File"), tr("You've made changes, press OK to save"),
                              QMessageBox::Ok | QMessageBox::Cancel, QMessageBox::Ok);
        if (reply == QMessageBox::Ok) {
            saveToConfFile();
        }
    }
    QString filePath = QFileDialog::getOpenFileName(this, tr("Open File"));
    QFile file(filePath);
    if (!file.open(QFile::ReadOnly | QFile::Text)) {
        qDebug() << "Open file failed";
        return;
    }
    QTextStream iss(&file);
    ui->confTextEdit->setPlainText(iss.readAll());
    fileChanged = false;
}

void ConfEditor::saveToConfFile() {
    QString filePath = QFileDialog::getSaveFileName(this, tr("Save File"));
    QFile file(filePath);
    file.open(QFile::WriteOnly | QFile::Text);
    if (!file.open(QFile::WriteOnly | QFile::Text)) {
        qDebug() << "Open file failed";
        return;
    }
    QTextStream oss(&file);
    oss << ui->confTextEdit->toPlainText();
    fileChanged = false;
}

void ConfEditor::initSignals() {
    connect(ui->addButton, &QPushButton::clicked, this, &ConfEditor::onAddButtonClicked);
    connect(ui->actionNew, &QAction::triggered, this, &ConfEditor::newConfFile);
    connect(ui->actionOpen, &QAction::triggered, this, &ConfEditor::openConfFile);
    connect(ui->actionSaveTo, &QAction::triggered, this, &ConfEditor::saveToConfFile);
    connect(ui->confTextEdit, &QPlainTextEdit::textChanged, [this]() {
        fileChanged = true;
    });
    connect(ui->actionCombo, &QComboBox::currentTextChanged, [this](const QString &text) {
        ui->cryptGroup->setVisible(text == tr("crypt"));
    });
}

static bool __check_ip_address(const QString &addr) {
    auto splits = addr.split(".");
    if (splits.size() != 4) return false;

    for (const auto &dec : splits) {
        bool ok;
        uint32_t number = dec.toUInt(&ok, 10);
        if (!ok || number > 255) {
            return false;
        }
    }

    return true;
}

bool ConfEditor::checkInput() {
    QString ip = ui->ipEdit->text();
    if (!__check_ip_address(ip)) {
        QMessageBox::warning(this, tr("Input Error"), tr("ip format error"));
        return false;
    }
    if (ui->actionCombo->currentText() == tr("crypt") && ui->keyEdit->text().isEmpty()) {
        QMessageBox::warning(this, tr("Input Error"), tr("key field must not be empty"));
        return false;
    }
    return true;
}
