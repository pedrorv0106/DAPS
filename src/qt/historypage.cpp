// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "historypage.h"
#include "ui_historypage.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
#include "guiconstants.h"
#include "bitcoingui.h"
#include "optionsmodel.h"
#include "walletmodel.h"

#include <QAction>
#include <QCursor>
#include <QItemSelection>
#include <QScrollBar>
#include <QTextDocument>

HistoryPage::HistoryPage(QWidget* parent) : QDialog(parent),
                                                          ui(new Ui::HistoryPage),
                                                          model(0)

{
    ui->setupUi(this);

}

HistoryPage::~HistoryPage()
{
    delete ui;
}

void HistoryPage::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
}


void HistoryPage::keyPressEvent(QKeyEvent* event)
{

    this->QDialog::keyPressEvent(event);
}
