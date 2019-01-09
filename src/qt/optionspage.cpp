// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "optionspage.h"
#include "ui_optionspage.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
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

OptionsPage::OptionsPage(QWidget* parent) : QDialog(parent),
                                                          ui(new Ui::OptionsPage),
                                                          model(0)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC // Icons on push buttons are very uncommon on Mac
    // #REMOVE ui->clearButton->setIcon(QIcon());
    ui->receiveButton->setIcon(QIcon());
    // #REMOVE ui->showRequestButton->setIcon(QIcon());
    // #REMOVE ui->removeRequestButton->setIcon(QIcon());
#endif

    // context menu actions
    // QAction* copyLabelAction = new QAction(tr("Copy label"), this);
    // QAction* copyMessageAction = new QAction(tr("Copy message"), this);
    // QAction* copyAmountAction = new QAction(tr("Copy amount"), this);

    // context menu
    // contextMenu = new QMenu();
    // contextMenu->addAction(copyLabelAction);
    // contextMenu->addAction(copyMessageAction);
    // contextMenu->addAction(copyAmountAction);

    // context menu signals
    // #REMOVE connect(ui->recentRequestsView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showMenu(QPoint)));
    // connect(copyLabelAction, SIGNAL(triggered()), this, SLOT(copyLabel()));
    // connect(copyMessageAction, SIGNAL(triggered()), this, SLOT(copyMessage()));
    // connect(copyAmountAction, SIGNAL(triggered()), this, SLOT(copyAmount()));

    // #REMOVE connect(ui->clearButton, SIGNAL(clicked()), this, SLOT(clear()));
}

void OptionsPage::setModel(WalletModel* model)
{
    this->model = model;

    if (model && model->getOptionsModel()) {
        model->getRecentRequestsTableModel()->sort(RecentRequestsTableModel::Date, Qt::DescendingOrder);
        //connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
        //updateDisplayUnit();

        // #REMOVE QTableView* tableView = ui->recentRequestsView;

        // #REMOVE tableView->verticalHeader()->hide();
        // #REMOVE tableView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        // #REMOVE tableView->setModel(model->getRecentRequestsTableModel());
        // #REMOVE tableView->setAlternatingRowColors(true);
        // #REMOVE tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
        // #REMOVE tableView->setSelectionMode(QAbstractItemView::ContiguousSelection);
        // #REMOVE tableView->setColumnWidth(RecentRequestsTableModel::Date, DATE_COLUMN_WIDTH);
        // #REMOVE tableView->setColumnWidth(RecentRequestsTableModel::Label, LABEL_COLUMN_WIDTH);

        // #REMOVE connect(tableView->selectionModel(),
        // #REMOVE     SIGNAL(selectionChanged(QItemSelection, QItemSelection)), this,
        // #REMOVE     SLOT(recentRequestsView_selectionChanged(QItemSelection, QItemSelection)));
        // Last 2 columns are set by the columnResizingFixer, when the table geometry is ready.
        // #REMOVE columnResizingFixer = new GUIUtil::TableViewLastColumnResizingFixer(tableView, AMOUNT_MINIMUM_COLUMN_WIDTH, DATE_COLUMN_WIDTH);
    }
}

OptionsPage::~OptionsPage()
{
    delete ui;
}

// void OptionsPage::clear()
// {
//     ui->reqAmount->clear();
//     // #REMOVE ui->reqLabel->setText("");
//     // #REMOVE ui->reqMessage->setText("");
//     // #REMOVE ui->reuseAddress->setChecked(false);
//     updateDisplayUnit();
// }

// void OptionsPage::reject()
// {
//     clear();
// }

// void OptionsPage::accept()
// {
//     clear();
// }

// void OptionsPage::updateDisplayUnit()
// {
//     // if (model && model->getOptionsModel()) {
//     //     ui->reqAmount->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
//     // }
// }

// void OptionsPage::on_receiveButton_clicked()
// {
//     if (!model || !model->getOptionsModel() || !model->getAddressTableModel() || !model->getRecentRequestsTableModel())
//         return;

//     QString address;
//     // #REMOVE QString label = ui->reqLabel->text();
//     // #REMOVE if (ui->reuseAddress->isChecked()) {
//         /* Choose existing receiving address */
//         // #REMOVE AddressBookPage dlg(AddressBookPage::ForSelection, AddressBookPage::ReceivingTab, this);
//         // #REMOVE dlg.setModel(model->getAddressTableModel());
//         // #REMOVE if (dlg.exec()) {
//         // #REMOVE     address = dlg.getReturnValue();
//         // #REMOVE     if (label.isEmpty()) /* If no label provided, use the previously used label */
//         // #REMOVE     {
//         // #REMOVE         label = model->getAddressTableModel()->labelForAddress(address);
//         // #REMOVE     }
//         // #REMOVE } else {
//         // #REMOVE     return;
//         // #REMOVE }
//     // #REMOVE } else {
//         /* Generate new receiving address */
//     // #REMOVE     address = model->getAddressTableModel()->addRow(AddressTableModel::Receive, label, "");
//     // #REMOVE }
//     // #REMOVE SendCoinsRecipient info(address, label,
//     // #REMOVE     ui->reqAmount->value(), ui->reqMessage->text());
//     // #REMOVE ReceiveRequestDialog* dialog = new ReceiveRequestDialog(this);
//    // #REMOVE  dialog->setAttribute(Qt::WA_DeleteOnClose);
//     // #REMOVE dialog->setModel(model->getOptionsModel());
//     // #REMOVE dialog->setInfo(info);
//     // #REMOVE dialog->show();
//     clear();

//     /* Store request for later reference */
//     // #REMOVE model->getRecentRequestsTableModel()->addNewRequest(info);
// }

// void OptionsPage::on_recentRequestsView_doubleClicked(const QModelIndex& index)
// {
//     // #REMOVE const RecentRequestsTableModel* submodel = model->getRecentRequestsTableModel();
//     // #REMOVE ReceiveRequestDialog* dialog = new ReceiveRequestDialog(this);
//     // #REMOVE dialog->setModel(model->getOptionsModel());
//     // #REMOVE dialog->setInfo(submodel->entry(index.row()).recipient);
//     // #REMOVE dialog->setAttribute(Qt::WA_DeleteOnClose);
//     // #REMOVE dialog->show();
// }

// void OptionsPage::recentRequestsView_selectionChanged(const QItemSelection& selected, const QItemSelection& deselected)
// {
//     // Enable Show/Remove buttons only if anything is selected.
//     // #REMOVE bool enable = !ui->recentRequestsView->selectionModel()->selectedRows().isEmpty();
//     // #REMOVE ui->showRequestButton->setEnabled(enable);
//     // #REMOVE ui->removeRequestButton->setEnabled(enable);
// }

// void OptionsPage::on_showRequestButton_clicked()
// {
//     // #REMOVE if (!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
//     // #REMOVE     return;
//     // #REMOVE QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();

//     // #REMOVE foreach (QModelIndex index, selection) {
//     // #REMOVE     on_recentRequestsView_doubleClicked(index);
//     // #REMOVE }
// }

// void OptionsPage::on_removeRequestButton_clicked()
// {
//     // #REMOVE if (!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
//     // #REMOVE     return;
//     // #REMOVE QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();
//     // #REMOVE if (selection.empty())
//     // #REMOVE     return;
//     // correct for selection mode ContiguousSelection
//     // #REMOVE QModelIndex firstIndex = selection.at(0);
//     // #REMOVE model->getRecentRequestsTableModel()->removeRows(firstIndex.row(), selection.length(), firstIndex.parent());
// }

// We override the virtual resizeEvent of the QWidget to adjust tables column
// sizes as the tables width is proportional to the dialogs width.
void OptionsPage::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
    // #REMOVE columnResizingFixer->stretchColumnWidth(RecentRequestsTableModel::Message);
}

void OptionsPage::keyPressEvent(QKeyEvent* event)
{
    // if (event->key() == Qt::Key_Return) {
    //     // press return -> submit form
    //     if (ui->reqAddress->hasFocus() || ui->reqAmount->hasFocus() || ui->reqID->hasFocus()) {
    //         event->ignore();
    //         on_receiveButton_clicked();
    //         return;
    //     }
    // }

    this->QDialog::keyPressEvent(event);
}

// copy column of selected row to clipboard
void OptionsPage::copyColumnToClipboard(int column)
{
    // #REMOVE if (!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
    // #REMOVE     return;
    // #REMOVE QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();
    // #REMOVE if (selection.empty())
    // #REMOVE     return;
    // correct for selection mode ContiguousSelection
    // #REMOVE QModelIndex firstIndex = selection.at(0);
    // #REMOVE GUIUtil::setClipboard(model->getRecentRequestsTableModel()->data(firstIndex.child(firstIndex.row(), column), Qt::EditRole).toString());
}

// context menu
// void OptionsPage::showMenu(const QPoint& point)
// {
//     // #REMOVE if (!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
//     // #REMOVE     return;
//     // #REMOVE QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();
//     // #REMOVE if (selection.empty())
//     // #REMOVE     return;
//     // #REMOVE contextMenu->exec(QCursor::pos());
// }

// // context menu action: copy label
// void OptionsPage::copyLabel()
// {
//     // #REMOVE copyColumnToClipboard(RecentRequestsTableModel::Label);
// }

// // context menu action: copy message
// void OptionsPage::copyMessage()
// {
//     // #REMOVE copyColumnToClipboard(RecentRequestsTableModel::Message);
// }

// // context menu action: copy amount
// void OptionsPage::copyAmount()
// {
//     // #REMOVE copyColumnToClipboard(RecentRequestsTableModel::Amount);
// }
