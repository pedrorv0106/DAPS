// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "receivecoinsdialog.h"
#include "ui_receivecoinsdialog.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "receiverequestdialog.h"
#include "recentrequeststablemodel.h"
#include "walletmodel.h"

#include <QAction>
#include <QClipboard>
#include <QCursor>
#include <QItemSelection>
#include <QMessageBox>
#include <QScrollBar>
#include <QTextDocument>

ReceiveCoinsDialog::ReceiveCoinsDialog(QWidget* parent) : QDialog(parent),
                                                          ui(new Ui::ReceiveCoinsDialog),
                                                          model(0)
{
    ui->setupUi(this);


    // context menu actions
    QAction* copyLabelAction = new QAction(tr("Copy label"), this);
    QAction* copyMessageAction = new QAction(tr("Copy message"), this);
    QAction* copyAmountAction = new QAction(tr("Copy amount"), this);

    // context menu
    contextMenu = new QMenu();
    contextMenu->addAction(copyLabelAction);
    contextMenu->addAction(copyMessageAction);
    contextMenu->addAction(copyAmountAction);

    // context menu signals
    connect(copyLabelAction, SIGNAL(triggered()), this, SLOT(copyLabel()));
    connect(copyMessageAction, SIGNAL(triggered()), this, SLOT(copyMessage()));
    connect(copyAmountAction, SIGNAL(triggered()), this, SLOT(copyAmount()));

    // Show privacy account address
    ui->lineEditAddress->setStyleSheet("border:none; background: transparent; text-align:center;");
    std::string pubAddress;
    pwalletMain->ComputeStealthPublicAddress("masteraccount", pubAddress);
    ui->lineEditAddress->setText(pubAddress.c_str());

    ui->pushButtonCP->setStyleSheet("background:transparent;");
    ui->pushButtonCP->setIcon(QIcon(":/icons/editcopy"));
    connect(ui->pushButtonCP, SIGNAL(clicked()), this, SLOT(copyAddress()));

}

void ReceiveCoinsDialog::setModel(WalletModel* model)
{
    this->model = model;

    if (model && model->getOptionsModel()) {
        model->getRecentRequestsTableModel()->sort(RecentRequestsTableModel::Date, Qt::DescendingOrder);
        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
        updateDisplayUnit();

        loadAccount();
    }
}

void ReceiveCoinsDialog::loadAccount() {
    //Set reqAddress as the master stealth address
    std::vector<std::string> addrList, accountList;
    CWallet* wl = model->getCWallet();
    QList<QString> stringsList;
    wl->AllMyPublicAddresses(addrList, accountList);
    for(int i = 0; i < addrList.size(); i++) {
        stringsList.append(QString(accountList[i].c_str()) + " - " + QString(addrList[i].c_str()));
    }

    ui->reqAddress->addItems(stringsList);
}

ReceiveCoinsDialog::~ReceiveCoinsDialog()
{
    delete ui;
}

void ReceiveCoinsDialog::clear()
{
    ui->reqAmount->clear();
    updateDisplayUnit();
}

void ReceiveCoinsDialog::reject()
{
    clear();
}

void ReceiveCoinsDialog::accept()
{
    clear();
}

void ReceiveCoinsDialog::updateDisplayUnit()
{
    if (model && model->getOptionsModel()) {
        ui->reqAmount->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    }
}

void ReceiveCoinsDialog::on_receiveButton_clicked()
{
    if (!model || !model->getOptionsModel() || !model->getAddressTableModel() || !model->getRecentRequestsTableModel())
        return;

    std::vector<std::string> addrList, accountList;
    CWallet* wl = model->getCWallet();
    wl->AllMyPublicAddresses(addrList, accountList);
    int selectedIdx = ui->reqAddress->currentIndex();
    if (addrList.size()>selectedIdx){
        QString address(addrList[selectedIdx].c_str());
        QString label(accountList[selectedIdx].c_str());
        QString reqMes = "Request message";
        QString strPaymentID = ui->reqID->text();
        if (!strPaymentID.trimmed().isEmpty()) {
            quint64 paymentID = strPaymentID.toULongLong();
            uint64_t id = paymentID;
            std::string integratedAddr;
            if (selectedIdx == 0) {
                wl->ComputeIntegratedPublicAddress(id, "masteraccount", integratedAddr);
            } else {
                wl->ComputeIntegratedPublicAddress(id, accountList[selectedIdx], integratedAddr);
            }
            address = QString(integratedAddr.c_str());
        }

        SendCoinsRecipient info(address, label,
            ui->reqAmount->value(), reqMes);
        ReceiveRequestDialog* dialog = new ReceiveRequestDialog(this);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setModel(model->getOptionsModel());
        dialog->setInfo(info);
        dialog->show();
        clear();
        model->getRecentRequestsTableModel()->addNewRequest(info);
    }

}

// We override the virtual resizeEvent of the QWidget to adjust tables column
// sizes as the tables width is proportional to the dialogs width.
void ReceiveCoinsDialog::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
}

void ReceiveCoinsDialog::keyPressEvent(QKeyEvent* event)
{
    if (event->key() == Qt::Key_Return) {
        // press return -> submit form
        if (ui->reqAddress->hasFocus() || ui->reqAmount->hasFocus() || ui->reqID->hasFocus()) {
            event->ignore();
            on_receiveButton_clicked();
            return;
        }
    }

    this->QDialog::keyPressEvent(event);
}

void ReceiveCoinsDialog::copyAddress(){
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(ui->lineEditAddress->text());
}