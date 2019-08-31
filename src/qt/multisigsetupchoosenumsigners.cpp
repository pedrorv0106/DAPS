#include "multisigsetupchoosenumsigners.h"
#include "ui_multisigsetupchoosenumsigners.h"
#include "guiutil.h"
#include "guiconstants.h"
#include "bitcoingui.h"

#include <QMessageBox>
#include <QCloseEvent>

MultiSigSetupChooseNumSigners::MultiSigSetupChooseNumSigners(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MultiSigSetupChooseNumSigners)
{
    ui->setupUi(this);

    connect(ui->btnNext, SIGNAL(clicked()), this, SLOT(on_btnNext()));
    connect(ui->btnCancel, SIGNAL(clicked()), this, SLOT(on_btnCancel()));
}

MultiSigSetupChooseNumSigners::~MultiSigSetupChooseNumSigners()
{
    delete ui;
}

void MultiSigSetupChooseNumSigners::setModel(WalletModel* model)
{
    this->model = model;
    if (pwalletMain->ReadNumSigners() >= 2) {
    	ui->numSignerSlider->setValue(pwalletMain->ReadNumSigners());
    }
}

void MultiSigSetupChooseNumSigners::closeEvent (QCloseEvent *event)
{
    QMessageBox::StandardButton reply;
    reply = QMessageBox::warning(this, "Multisig wallet setup required", "You need to configure multisig wallet to use?", QMessageBox::Retry|QMessageBox::Close);
      if (reply == QMessageBox::Retry) {
      event->ignore();
      } else {
    	  pwalletMain->isMultisigSetupFinished = true;
    	  QApplication::quit();
      }
}

void MultiSigSetupChooseNumSigners::on_btnCancel()
{
    QMessageBox::StandardButton reply;
    reply = QMessageBox::warning(this, "Multisig wallet setup required", "You need to configure multisig wallet to use?", QMessageBox::Retry|QMessageBox::Close);
      if (reply == QMessageBox::Retry) {
      return;
      } else {
    	  pwalletMain->isMultisigSetupFinished = true;
    	  QApplication::quit();
      }
}

void MultiSigSetupChooseNumSigners::on_btnNext()
{
	int val = ui->numSignerSlider->value();
	if (pwalletMain) {
		pwalletMain->SetNumSigners(val);
		pwalletMain->screenIndex++;
	}
	accept();
}
