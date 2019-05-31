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
private:
    void update();

private slots:
    void on_btnCopyURI_clicked();


private:
    Ui::TwoFAQRDialog *ui;
};

#endif // TWOFAQRDIALOG_H
