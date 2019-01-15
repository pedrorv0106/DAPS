// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_HISTORYPAGE_H
#define BITCOIN_QT_HISTORYPAGE_H

#include "guiutil.h"
#include "togglebutton.h"

#include <QDialog>
#include <QHeaderView>
#include <QItemSelection>
#include <QKeyEvent>
#include <QMenu>
#include <QPoint>
#include <QVariant>
#include <QSettings>

class WalletModel;

namespace Ui
{
class HistoryPage;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
class QDataWidgetMapper;
QT_END_NAMESPACE

/** Dialog for options page */
class HistoryPage : public QDialog
{
    Q_OBJECT

public:
    explicit HistoryPage(QWidget* parent = 0);
    ~HistoryPage();

public slots:

protected:
    virtual void keyPressEvent(QKeyEvent* event);

private:
    Ui::HistoryPage* ui;
    GUIUtil::TableViewLastColumnResizingFixer* columnResizingFixer;
    WalletModel* model;
    virtual void resizeEvent(QResizeEvent* event);

private slots:
};

#endif // BITCOIN_QT_HISTORYPAGE_H
