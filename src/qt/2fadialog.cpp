#include "2fadialog.h"
#include "ui_2fadialog.h"

TwoFADialog::TwoFADialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::TwoFADialog)
{
    ui->setupUi(this);

    ui->txtcode_1->setAlignment(Qt::AlignCenter);
    ui->txtcode_2->setAlignment(Qt::AlignCenter);
    ui->txtcode_3->setAlignment(Qt::AlignCenter);
    ui->txtcode_4->setAlignment(Qt::AlignCenter);
    ui->txtcode_5->setAlignment(Qt::AlignCenter);
    ui->txtcode_6->setAlignment(Qt::AlignCenter);

    connect(ui->btnOK, SIGNAL(clicked()), this, SLOT(on_acceptCode()));
    connect(ui->btnCancel, SIGNAL(clicked()), this, SLOT(reject()));

}

TwoFADialog::~TwoFADialog()
{
    delete ui;
}

void TwoFADialog::on_acceptCode()
{
    QString code;
    char code1, code2, code3, code4, code5, code6;
    QString input;
    char* chrlist;

    input = ui->txtcode_1->toPlainText();
    chrlist = input.toUtf8().data();
    code1 = chrlist[0];

    input = ui->txtcode_2->toPlainText();
    chrlist = input.toUtf8().data();
    code2 = chrlist[0];

    input = ui->txtcode_3->toPlainText();
    chrlist = input.toUtf8().data();
    code3 = chrlist[0];

    input = ui->txtcode_4->toPlainText();
    chrlist = input.toUtf8().data();
    code4 = chrlist[0];

    input = ui->txtcode_5->toPlainText();
    chrlist = input.toUtf8().data();
    code5 = chrlist[0];

    input = ui->txtcode_6->toPlainText();
    chrlist = input.toUtf8().data();
    code6 = chrlist[0];

    code.sprintf("%c%c%c%c%c%c", code1, code2, code3, code4, code5, code6);
    settings.setValue("2FACode", code);

    accept();
}