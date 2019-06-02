#include "2faqrdialog.h"
#include "ui_2faqrdialog.h"
#include "receiverequestdialog.h"
#include "guiconstants.h"

#include <QClipboard>
#include <QDrag>
#include <QMenu>
#include <QMimeData>
#include <QMouseEvent>
#include <QPixmap>
#if QT_VERSION < 0x050000
#include <QUrl>
#endif

// #define USE_QRCODE

#if defined(HAVE_CONFIG_H)
#include "config/dapscoin-config.h" /* for USE_QRCODE */
#endif

#ifdef USE_QRCODE
#include <qrencode.h>
#endif

TwoFAQRDialog::TwoFAQRDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::TwoFAQRDialog)
{
    ui->setupUi(this);

#ifndef USE_QRCODE
    ui->lblQRCode->setVisible(false);
#endif

    connect(ui->btnCopy, SIGNAL(clicked()), this, SLOT(on_btnCopyURI_clicked()));
    connect(ui->btnNext, SIGNAL(clicked()), this, SLOT(accept()));
	connect(ui->btnCancel, SIGNAL(clicked()), this, SLOT(reject()));
    update();
}

TwoFAQRDialog::~TwoFAQRDialog()
{
    delete ui;
}

void TwoFAQRDialog::update()
{
    QString uri = "otpauth://totp/dapscoin:john@example.com?secret=PUBLICKEY&issuer=dapscoin&algorithm=SHA1&digits=6&period=30";
    ui->lblURI->setText(uri);

#ifdef USE_QRCODE
    ui->lblQRCode->setText("");
    if (!uri.isEmpty()) {
        // limit URI length
        if (uri.length() > MAX_URI_LENGTH) {
            ui->lblQRCode->setText(tr("Resulting URI too long, try to reduce the text for label / message."));
        } else {
            QRcode* code = QRcode_encodeString(uri.toUtf8().constData(), 0, QR_ECLEVEL_L, QR_MODE_8, 1);
            if (!code) {
                ui->lblQRCode->setText(tr("Error encoding URI into QR Code."));
                return;
            }
            QImage myImage = QImage(code->width + 8, code->width + 8, QImage::Format_RGB32);
            myImage.fill(0xffffff);
            unsigned char* p = code->data;
            for (int y = 0; y < code->width; y++) {
                for (int x = 0; x < code->width; x++) {
                    myImage.setPixel(x + 4, y + 4, ((*p & 1) ? 0x0 : 0xffffff));
                    p++;
                }
            }
            QRcode_free(code);

            ui->lblQRCode->setPixmap(QPixmap::fromImage(myImage).scaled(300, 300));
        }
    }
#endif
}

void TwoFAQRDialog::on_btnCopyURI_clicked()
{
    GUIUtil::setClipboard(ui->lblURI->text());
}