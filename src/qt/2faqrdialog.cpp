#include "2faqrdialog.h"
#include "ui_2faqrdialog.h"

#include <QClipboard>

TwoFAQRDialog::TwoFAQRDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::TwoFAQRDialog)
{
    ui->setupUi(this);
}

TwoFAQRDialog::~TwoFAQRDialog()
{
    delete ui;
}