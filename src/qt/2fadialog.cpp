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
    accept();
}