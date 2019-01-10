// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "optionspage.h"
#include "ui_optionspage.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
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
    settings.setValue("theme", "dark");
    GUIUtil::refreshStyleSheet();
    ui->pushButtonDarkMode->setChecked(true);
    ui->pushButtonLightMode->setChecked(false);
}

void OptionsPage::on_pushButtonLightMode_clicked()
{
    if (!model || !model->getOptionsModel())
        return;
    settings.setValue("theme", "light");
    GUIUtil::refreshStyleSheet();
    ui->pushButtonLightMode->setChecked(true);
    ui->pushButtonDarkMode->setChecked(false);
}

