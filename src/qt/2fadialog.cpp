#include "2fadialog.h"
#include "ui_2fadialog.h"

TwoFADialog::TwoFADialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::TwoFADialog)
{
    ui->setupUi(this);

}

TwoFADialog::~TwoFADialog()
{
    delete ui;
}