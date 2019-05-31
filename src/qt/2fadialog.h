#ifndef TWOFADIALOG_H
#define TWOFADIALOG_H

#include <QDialog>

namespace Ui {
class TwoFADialog;
}

class TwoFADialog : public QDialog
{
    Q_OBJECT

public:
    explicit TwoFADialog(QWidget *parent = 0);
    ~TwoFADialog();

private slots:
    void on_acceptCode();

private:
    Ui::TwoFADialog *ui;
};

#endif // TWOFADIALOG_H
