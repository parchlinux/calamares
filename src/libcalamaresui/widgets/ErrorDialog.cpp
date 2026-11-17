/* === This file is part of Calamares - <https://calamares.io> ===
 *
 *   SPDX-FileCopyrightText: 2021 Artem Grinev <agrinev@manjaro.org>
 *   SPDX-License-Identifier: GPL-3.0-or-later
 *
 *   Calamares is Free Software: see the License-Identifier above.
 *
 */

#include "ErrorDialog.h"
#include "ui_ErrorDialog.h"

#include "utils/Logger.h"
#include "widgets/TranslationFix.h"
#include <QClipboard>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QGuiApplication>
#include <QIcon>
#include <QPushButton>
#include <QStandardPaths>
#include <QTextStream>

namespace Calamares
{

ErrorDialog::ErrorDialog( QWidget* parent )
    : QDialog( parent )
    , ui( new Ui::ErrorDialog )
{
    ui->setupUi( this );
    ui->iconLabel->setPixmap( QIcon::fromTheme( "dialog-error" ).pixmap( 64 ) );
    ui->detailsWidget->hide();
    ui->offerWebPasteLabel->hide();

    auto* saveLogBtn = ui->buttonBox->addButton( tr( "Save Log to Desktop" ), QDialogButtonBox::ActionRole );
    connect( saveLogBtn, &QPushButton::clicked, this, [ this, saveLogBtn ] {
        QString desktopPath = QStandardPaths::writableLocation( QStandardPaths::DesktopLocation );
        if ( desktopPath.isEmpty() || !QDir( desktopPath ).exists() )
        {
            for ( const auto& candidate : { QStringLiteral( "/home/parch/Desktop" ),
                                           QStringLiteral( "/home/parch" ),
                                           QDir::homePath() } )
            {
                if ( QDir( candidate ).exists() )
                {
                    desktopPath = candidate;
                    break;
                }
            }
        }
        if ( desktopPath.isEmpty() )
        {
            desktopPath = QStringLiteral( "/tmp" );
        }
        QString targetFile = desktopPath + QStringLiteral( "/parch-install-error.log" );

        QString sourceLog = Logger::logFile();
        if ( sourceLog.isEmpty() || !QFile::exists( sourceLog ) )
        {
            sourceLog = QStringLiteral( "/root/.cache/calamares/session.log" );
        }

        QFile out( targetFile );
        if ( out.open( QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate ) )
        {
            QTextStream stream( &out );
            stream << "=== Parch Linux Installation Failure Report ===\n";
            stream << "Date: " << QDateTime::currentDateTime().toString( Qt::ISODate ) << "\n";
            stream << "Failure Message: " << informativeText() << "\n";
            stream << "Failure Details:\n" << details() << "\n";
            stream << "================================================\n\n";

            QFile src( sourceLog );
            if ( src.open( QIODevice::ReadOnly ) )
            {
                stream << src.readAll();
                src.close();
            }
            out.close();

            if ( QGuiApplication::clipboard() )
            {
                QGuiApplication::clipboard()->setText(
                    QStringLiteral( "Parch Linux Install Error:\n%1\n\nDetails:\n%2\n\nLog saved to: %3" )
                        .arg( informativeText(), details(), targetFile ) );
            }
            saveLogBtn->setText( tr( "Log Saved to Desktop!" ) );
            saveLogBtn->setEnabled( false );
        }
    } );
}

ErrorDialog::~ErrorDialog()
{
    delete ui;
}

QString
ErrorDialog::heading() const
{
    return ui->headingLabel->text();
}

QString
ErrorDialog::informativeText() const
{
    return ui->informativeTextLabel->text();
}

QString
ErrorDialog::details() const
{
    return ui->detailsBrowser->toPlainText();
}

void
ErrorDialog::setHeading( const QString& newHeading )
{
    if ( ui->headingLabel->text() != newHeading )
    {
        ui->headingLabel->setText( newHeading );
        emit headingChanged();
    }
}

void
ErrorDialog::setInformativeText( const QString& newInformativeText )
{
    if ( ui->informativeTextLabel->text() != newInformativeText )
    {
        ui->informativeTextLabel->setText( newInformativeText );
        emit informativeTextChanged();
    }
}

void
ErrorDialog::setDetails( const QString& newDetails )
{
    if ( ui->detailsBrowser->toPlainText() != newDetails )
    {
        ui->detailsBrowser->setPlainText( newDetails );
        ui->detailsWidget->setVisible( !ui->detailsBrowser->toPlainText().trimmed().isEmpty() );
        emit detailsChanged();
    }
}

bool
ErrorDialog::shouldOfferWebPaste() const
{
    return m_shouldOfferWebPaste;
}

void
ErrorDialog::setShouldOfferWebPaste( bool newShouldOfferWebPaste )
{
    if ( m_shouldOfferWebPaste != newShouldOfferWebPaste )
    {
        m_shouldOfferWebPaste = newShouldOfferWebPaste;

        ui->offerWebPasteLabel->setVisible( m_shouldOfferWebPaste );
        ui->buttonBox->setStandardButtons( m_shouldOfferWebPaste ? ( QDialogButtonBox::Yes | QDialogButtonBox::No )
                                                                 : QDialogButtonBox::Close );
        fixButtonLabels( ui->buttonBox );

        emit shouldOfferWebPasteChanged();
    }
}

}  // namespace Calamares
