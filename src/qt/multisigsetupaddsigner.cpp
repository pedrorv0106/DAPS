#include "multisigsetupaddsigner.h"
#include "ui_multisigsetupaddsigner.h"
#include "guiutil.h"
#include "guiconstants.h"
#include "bitcoingui.h"

#include <QMessageBox>
#include <QCloseEvent>

MultiSigSetupAddSigner::MultiSigSetupAddSigner(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MultiSigSetupAddSigner)
{
    ui->setupUi(this);

    connect(ui->btnNext, SIGNAL(clicked()), this, SLOT(on_btnNext()));
    connect(ui->btnBack, SIGNAL(clicked()), this, SLOT(on_btnBack()));
}

MultiSigSetupAddSigner::~MultiSigSetupAddSigner()
{
    delete ui;
}

void MultiSigSetupAddSigner::setModel(WalletModel* model)
{
    this->model = model;
    ComboKey mine = pwalletMain->MyComboKey();
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << mine;
    std::string hex = HexStr(ssTx.begin(), ssTx.end());
    if (pwalletMain->screenIndex > 1) {
    	if (pwalletMain->screenIndex <= pwalletMain->comboKeys.comboKeys.size()) {
    		CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    		ssTx << pwalletMain->comboKeys.comboKeys[pwalletMain->screenIndex - 1];
    		hex = HexStr(ssTx.begin(), ssTx.end());
    	    ui->textComboKey->setText(QString::fromStdString(hex));
    	}
    } else {
        ui->textComboKey->setReadOnly(true);
        ui->textComboKey->setText(QString::fromStdString(hex));
    }
    if (pwalletMain->screenIndex == 1) {
        ui->label->setText(QString::fromStdString("My Combo Key (1 of " + std::to_string(pwalletMain->ReadNumSigners())) + ")");
    	std::string labelText = "This is your combo key, consisting of your multisignature keychain wallet's public spend key, \nand private view key. Send this combo key to your" + std::to_string(pwalletMain->ReadNumSigners()) + " co-signers";
    	ui->label_2->setText(QString::fromStdString(labelText));
    } else {
        ui->label->setText(QString::fromStdString("Add Co-Signer (" + std::to_string(pwalletMain->screenIndex) + " of " + std::to_string(pwalletMain->ReadNumSigners())) + ")");
        std::string labelText = "Enter the combo key of your co-signer. \nEnter their combo key if you want to be able to sign for them";
        ui->label_2->setText(QString::fromStdString(labelText));
    }
}

void MultiSigSetupAddSigner::closeEvent (QCloseEvent *event)
{
    QMessageBox::StandardButton reply;
    reply = QMessageBox::warning(this, "Multisig wallet setup required", "You need to configure multisig wallet to use?", QMessageBox::Retry|QMessageBox::Close);
      if (reply == QMessageBox::Retry) {
      event->ignore();
      } else {
      QApplication::quit();
      }
}

void MultiSigSetupAddSigner::on_btnBack()
{
	if (pwalletMain) {
		pwalletMain->screenIndex--;
	}
    accept();
}

void MultiSigSetupAddSigner::on_btnNext()
{
	std::string hexCombo = ui->textComboKey->toPlainText().toStdString();
	if (!IsHex(hexCombo)) return;
	vector<unsigned char> comboData(ParseHex(hexCombo));
	CDataStream ssdata(comboData, SER_NETWORK, PROTOCOL_VERSION);
	ComboKey combo;
	try {
		ssdata >> combo;
	} catch (const std::exception&) {
		return;
	}
	if (pwalletMain) {
		pwalletMain->AddCosignerKeyAtIndex(combo, pwalletMain->screenIndex);
		pwalletMain->screenIndex++;
		LogPrintf("Successfully added a combo key");
	}
	accept();
}
