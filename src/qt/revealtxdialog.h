#ifndef REVEALTXDIALOG_H
#define REVEALTXDIALOG_H

#include <QDialog>

namespace Ui {
class RevealTxDialog;
}

class RevealTxDialog : public QDialog
{
    Q_OBJECT

public:
    explicit RevealTxDialog(QWidget *parent = 0);
    ~RevealTxDialog();

    void setTxID(QString strId);
    void setTxAddress(QString strAddr);
    void setTxPrivKey(QString strPrivKey);

private slots:
    void on_buttonBox_accepted();
    void copyID();
    void copyAddress();
    void copyPrivateKey();

private:
    Ui::RevealTxDialog *ui;
};

#endif // REVEALTXDIALOG_H
