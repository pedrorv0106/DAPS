// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "optionspage.h"
#include "ui_optionspage.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
#include "guiconstants.h"
#include "bitcoingui.h"
#include "optionsmodel.h"
#include "receiverequestdialog.h"
#include "recentrequeststablemodel.h"
#include "walletmodel.h"

#include <QAction>
#include <QCursor>
#include <QItemSelection>
#include <QMessageBox>
#include <QScrollBar>
#include <QTextDocument>
#include <QDataWidgetMapper>
#include <QTextStream>

OptionsPage::OptionsPage(QWidget* parent) : QDialog(parent),
                                                          ui(new Ui::OptionsPage),
                                                          model(0),
                                                          mapper(0)
{
    ui->setupUi(this);

    connect(ui->pushButtonDarkMode, SIGNAL(clicked()), this, SLOT(showRestartWarning()));
    connect(ui->pushButtonLightMode, SIGNAL(clicked()), this, SLOT(showRestartWarning()));

    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);

    ui->pushButtonDarkMode->setObjectName("toggleButton");
    ui->pushButtonDarkMode->setCheckable(true);
    ui->pushButtonDarkMode->setChecked(settings.value("theme")=="dark");
    if (settings.value("theme")=="dark")
        ui->pushButtonLightMode->stackUnder(ui->pushButtonDarkMode);
    ui->pushButtonLightMode->setObjectName("toggleButton");
    ui->pushButtonLightMode->setCheckable(true);
    ui->pushButtonLightMode->setChecked(settings.value("theme")=="light");
    ui->pushButton2FAOn->setObjectName("toggleButton");
    ui->pushButton2FAOff->setObjectName("toggleButton");

    connect(ui->lineEditNewPass, SIGNAL(textChanged(const QString &)), this, SLOT(validateNewPass()));
    connect(ui->lineEditNewPassRepeat, SIGNAL(textChanged(const QString &)), this, SLOT(validateNewPassRepeat()));
}

void OptionsPage::setModel(WalletModel* model)
{
    this->model = model;
    this->options = model->getOptionsModel();

    if (model && model->getOptionsModel()) {
        model->getRecentRequestsTableModel()->sort(RecentRequestsTableModel::Date, Qt::DescendingOrder);
    }

    mapper->setModel(options);
    setMapper();
    mapper->toFirst();
}

OptionsPage::~OptionsPage()
{
    delete ui;
}


// We override the virtual resizeEvent of the QWidget to adjust tables column
// sizes as the tables width is proportional to the dialogs width.
void OptionsPage::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
}


void OptionsPage::keyPressEvent(QKeyEvent* event)
{

    this->QDialog::keyPressEvent(event);
}

void OptionsPage::setMapper()
{
    //mapper->addMapping([component], OptionsModel::[setting]);
}

void OptionsPage::on_pushButtonDarkMode_clicked()
{
    if (!model || !model->getOptionsModel())
        return;
    ui->pushButtonDarkMode->setChecked(true);
    ui->pushButtonLightMode->setChecked(false);
    ui->pushButtonLightMode->stackUnder(ui->pushButtonDarkMode);
    ui->pushButtonDarkMode->parentWidget()->repaint();
    settings.setValue("theme", "dark");
    GUIUtil::refreshStyleSheet();
}

void OptionsPage::on_pushButtonLightMode_clicked()
{
    if (!model || !model->getOptionsModel())
        return;
    ui->pushButtonLightMode->setChecked(true);
    ui->pushButtonDarkMode->setChecked(false);
    ui->pushButtonDarkMode->stackUnder(ui->pushButtonLightMode);
    ui->pushButtonDarkMode->parentWidget()->repaint();
    settings.setValue("theme", "light");
    GUIUtil::refreshStyleSheet();
}

void OptionsPage::on_pushButtonPassword_clicked()
{
    SecureString oldPass = SecureString();
    oldPass.reserve(MAX_PASSPHRASE_SIZE);
    oldPass.assign( ui->lineEditOldPass->text().toStdString().c_str() );
    SecureString newPass = SecureString();
    newPass.reserve(MAX_PASSPHRASE_SIZE);
    oldPass.assign( ui->lineEditNewPass->text().toStdString().c_str() );

    if ( (ui->lineEditNewPass->text() == ui->lineEditNewPassRepeat->text()) && (ui->lineEditNewPass->text().length()) )
    {
        if (!model->getEncryptionStatus()){
            model->setWalletEncrypted(true, newPass);
        } else {
            if (model->changePassphrase(oldPass,newPass)) {
                ui->lineEditOldPass->setStyleSheet(GUIUtil::loadStyleSheet());
            } else {
                ui->lineEditOldPass->setStyleSheet("border-color:red");
            }
        }
        ui->lineEditOldPass->repaint();
    }
}

void OptionsPage::validateNewPass()
{
    matchNewPasswords();
}

void OptionsPage::validateNewPassRepeat()
{
    matchNewPasswords();
}

bool OptionsPage::matchNewPasswords()
{
    if (ui->lineEditNewPass->text()==ui->lineEditNewPassRepeat->text())
    {
        ui->lineEditNewPassRepeat->setStyleSheet(GUIUtil::loadStyleSheet());
        ui->lineEditNewPassRepeat->repaint();
        return true;
    } else
    {
        ui->lineEditNewPassRepeat->setStyleSheet("border-color: red");
        ui->lineEditNewPassRepeat->repaint();
        return false;
    }
}