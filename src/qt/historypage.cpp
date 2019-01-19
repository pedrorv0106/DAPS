// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "historypage.h"
#include "ui_historypage.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoingui.h"
#include "bitcoinunits.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "transactionrecord.h"
#include "walletmodel.h"

#include <QAction>
#include <QBrush>
#include <QCalendarWidget>
#include <QCursor>
#include <QItemSelection>
#include <QScrollBar>
#include <QSortFilterProxyModel>
#include <QTextDocument>
#include <QTime>

HistoryPage::HistoryPage(QWidget* parent) : QDialog(parent),
                                            ui(new Ui::HistoryPage),
                                            model(0)

{
    ui->setupUi(this);

    initWidgets();
    connectWidgets();
    updateTableData();
}


HistoryPage::~HistoryPage()
{
    delete ui;
}
void HistoryPage::initWidgets()
{
    ui->tableView->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->tableView->setAttribute(Qt::WA_TranslucentBackground, true);
    //
    ui->dateTimeEditTo->setDisplayFormat("M/d/yy");
    ui->dateTimeEditFrom->setDisplayFormat("M/d/yy");
    ui->dateTimeEditTo->setDateTime(QDateTime::currentDateTime().addDays(1));
    ui->dateTimeEditFrom->setDateTime(QDateTime::currentDateTime().addDays(-7));
    //add QTimeEdit's to QCalendar popups
    timeEditTo = new QTimeEdit(ui->dateTimeEditTo);
    timeEditFrom = new QTimeEdit(ui->dateTimeEditFrom);
    ui->dateTimeEditTo->calendarWidget()->parentWidget()->layout()->addWidget(timeEditTo);
    ui->dateTimeEditFrom->calendarWidget()->parentWidget()->layout()->addWidget(timeEditFrom);
    //remove window frames from widgets
    GUIUtil::setWindowless(ui->dateTimeEditTo->calendarWidget()->parentWidget());
    GUIUtil::setWindowless(ui->dateTimeEditFrom->calendarWidget()->parentWidget());
    GUIUtil::setWindowless(ui->comboBoxType->view()->parentWidget());
    //color calendarwidgets
    GUIUtil::colorCalendarWidgetWeekends(ui->dateTimeEditTo->calendarWidget(), QColor("gray"));
    GUIUtil::colorCalendarWidgetWeekends(ui->dateTimeEditFrom->calendarWidget(), QColor("gray"));
}

void HistoryPage::connectWidgets() //add functions to widget signals
{
    connect(ui->dateTimeEditTo, SIGNAL(dateChanged(const QDate&)), this, SLOT(updateFilter()));
    connect(ui->dateTimeEditFrom, SIGNAL(dateChanged(const QDate&)), this, SLOT(updateFilter()));
    connect(ui->comboBoxType, SIGNAL(currentIndexChanged(const int&)), this, SLOT(updateFilter()));
    connect(ui->lineEditDesc, SIGNAL(textChanged(const QString&)), this, SLOT(updateFilter()));
    connect(ui->lineEditAmount, SIGNAL(textChanged(const QString&)), this, SLOT(updateFilter()));
    //
    connect(timeEditFrom, SIGNAL(timeChanged(const QTime&)), this, SLOT(updateFilter()));
    connect(timeEditTo, SIGNAL(timeChanged(const QTime&)), this, SLOT(updateFilter()));
}

void HistoryPage::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
    ui->tableView->setColumnWidth(2, this->width() * .45);
    ui->tableView->resizeColumnToContents(QHeaderView::ResizeToContents);
    ui->tableView->resizeColumnsToContents();
}


void HistoryPage::keyPressEvent(QKeyEvent* event)
{
    this->QDialog::keyPressEvent(event);
}

void HistoryPage::addTableData(std::map<QString, QString>)
{
}

void HistoryPage::updateTableData()
{
    auto txs = WalletUtil::getTXs(pwalletMain);
    for (int row = 0; row < (short)txs.size(); row++) {
        ui->tableView->insertRow(row);
        int col = 0;
        for (QString dataName : {"date", "type", "address", "amount"}) {
            QString data = txs[row].at(dataName);
            QString date = QDateTime::fromString(data, "M/dd/yy hh:mm").addYears(100).toString("MM/dd/20yy h:m");
            QTableWidgetItem* cell = new QTableWidgetItem();
            switch (col) {
            case 0: /*date*/
                cell->setData(0, date);
                break;
            default:
                cell->setData(0, data);
                break;
            }
            ui->tableView->setItem(row, col, cell);
            col++;
        }
    }
}

void HistoryPage::updateFilter()
{
    syncTime(ui->dateTimeEditFrom, timeEditFrom);
    syncTime(ui->dateTimeEditFrom, timeEditFrom);
    auto selectedAmount = ui->lineEditAmount->text().toFloat();
    QString selectedType = ui->comboBoxType->currentText();

    for (int row = 0; row < ui->tableView->rowCount(); row++) {
        bool hide = false;
        QDateTime date = QDateTime::fromString(ui->tableView->item(row, 0)->text(), "M/d/yyyy h:m");
        QString type = ui->tableView->item(row, 1)->text();
        QString address = ui->tableView->item(row, 2)->text();
        auto amount = ui->tableView->item(row, 3)->text().toFloat();

        if (
            (ui->dateTimeEditFrom->dateTime() > date) || (ui->dateTimeEditTo->dateTime() < date) || //record is not between selected dates
            (!address.contains(ui->lineEditDesc->text())) ||                                        //record address does not contain selected address
            (amount < selectedAmount)                                                               //record smaller than selected min amount
        )
            hide = true;
        if (selectedType != "All") {
            if (selectedType == "Received") {
                hide = !(type == "Received" || type == "Masternode Reward" || type == "Staking Reward" || type == "PoA Reward");
            } else
                hide = (selectedType != type);
        }

        ui->tableView->setRowHidden(row, hide);
    }
}

void HistoryPage::syncTime(QDateTimeEdit* calendar, QTimeEdit* clock)
{
    calendar->setTime(clock->time());
}