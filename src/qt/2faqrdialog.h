#ifndef TWOFAQRDIALOG_H
#define TWOFAQRDIALOG_H

#include <QDialog>

namespace Ui {
class TwoFAQRDialog;
}

class TwoFAQRDialog : public QDialog
{
    Q_OBJECT

public:
    explicit TwoFAQRDialog(QWidget *parent = 0);
    ~TwoFAQRDialog();

private slots:

private:
    Ui::TwoFAQRDialog *ui;
};

#endif // TWOFAQRDIALOG_H
