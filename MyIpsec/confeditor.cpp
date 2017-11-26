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

    setFixedSize(size());
    ui->saveButton->setEnabled(false);
    fileChanged = false;
    initSignals();
}

ConfEditor::~ConfEditor()
{
    delete ui;
}

void ConfEditor::load(QString config) {
    ui->confTextEdit->setPlainText(config);
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
    emit configChanged();
}

void ConfEditor::onSaveButtonClicked() {
    emit saved(ui->confTextEdit->toPlainText());
    close();
}

void ConfEditor::initSignals() {
    connect(ui->addButton, &QPushButton::clicked, this, &ConfEditor::onAddButtonClicked);
    connect(ui->saveButton, &QPushButton::clicked, this, &ConfEditor::onSaveButtonClicked);
    connect(ui->confTextEdit, &QPlainTextEdit::textChanged, [this]() {
        if (isHidden()) return;
        emit configChanged();
    });
    connect(ui->actionCombo, &QComboBox::currentTextChanged, [this](const QString &text) {
        ui->cryptGroup->setVisible(text == tr("crypt"));
    });
    connect(this, &ConfEditor::configChanged, [this]() {
        fileChanged = true;
        ui->saveButton->setEnabled(true);
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
