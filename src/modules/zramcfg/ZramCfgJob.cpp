/* === This file is part of Calamares - <https://calamares.io> ===
 *
 *   SPDX-FileCopyrightText: 2026 Parch Linux
 *   SPDX-License-Identifier: GPL-3.0-or-later
 *
 */

#include "ZramCfgJob.h"

#include "GlobalStorage.h"
#include "JobQueue.h"
#include "utils/Logger.h"

#include <QDir>
#include <QFile>
#include <QTextStream>

ZramCfgJob::ZramCfgJob( QObject* parent )
    : Calamares::CppJob( parent )
    , m_algorithm( QStringLiteral( "zstd" ) )
    , m_size( QStringLiteral( "min(ram, 8192)" ) )
{
}

ZramCfgJob::~ZramCfgJob()
{
}

QString
ZramCfgJob::prettyName() const
{
    return tr( "Configuring ZRAM compressed memory swap..." );
}

void
ZramCfgJob::setConfigurationMap( const QVariantMap& configurationMap )
{
    if ( configurationMap.contains( "algorithm" ) )
    {
        m_algorithm = configurationMap.value( "algorithm" ).toString().trimmed();
    }
    if ( configurationMap.contains( "size" ) )
    {
        m_size = configurationMap.value( "size" ).toString().trimmed();
    }
}

Calamares::JobResult
ZramCfgJob::exec()
{
    Calamares::GlobalStorage* gs = Calamares::JobQueue::instance()->globalStorage();
    if ( !gs || !gs->contains( "rootMountPoint" ) )
    {
        cWarning() << "zramcfg: No *rootMountPoint* defined.";
        return Calamares::JobResult::internalError(
            tr( "Configuration Error" ),
            tr( "No root mount point is set for zramcfg." ),
            Calamares::JobResult::InvalidConfiguration );
    }

    QString root = gs->value( "rootMountPoint" ).toString();

    // Check if on-disk swap was configured
    bool hasDiskSwap = false;

    // 1. Check partitionChoices (automatic partitioning mode)
    if ( gs->contains( "partitionChoices" ) )
    {
        QVariantMap choices = gs->value( "partitionChoices" ).toMap();
        QString swapChoice = choices.value( "swap" ).toString().trimmed().toLower();
        if ( swapChoice == QStringLiteral( "file" ) ||
             swapChoice == QStringLiteral( "small" ) ||
             swapChoice == QStringLiteral( "suspend" ) )
        {
            hasDiskSwap = true;
            cDebug() << "zramcfg: Detected swap choice from partitionChoices:" << swapChoice;
        }
    }

    // 2. Check partitions list (manual and automatic partitioning)
    if ( !hasDiskSwap && gs->contains( "partitions" ) )
    {
        const QVariantList partitions = gs->value( "partitions" ).toList();
        for ( const auto& pVar : partitions )
        {
            const QVariantMap p = pVar.toMap();
            const QString fs = p.value( "fs" ).toString().trimmed().toLower();
            const QString mountPoint = p.value( "mountPoint" ).toString().trimmed().toLower();
            if ( fs == QStringLiteral( "swap" ) ||
                 fs == QStringLiteral( "linuxswap" ) ||
                 mountPoint == QStringLiteral( "swap" ) ||
                 mountPoint == QStringLiteral( "/swap" ) )
            {
                hasDiskSwap = true;
                cDebug() << "zramcfg: Detected swap partition in partitions list:" << p.value( "device" ).toString();
                break;
            }
        }
    }

    if ( hasDiskSwap )
    {
        cDebug() << "zramcfg: On-disk swap is configured. Automatic zram is not required.";
        return Calamares::JobResult::ok();
    }

    cDebug() << "zramcfg: No on-disk swap detected. Automatically enabling zram-generator.";

    QDir systemdDir( root + QStringLiteral( "/etc/systemd" ) );
    if ( !systemdDir.exists() )
    {
        if ( !systemdDir.mkpath( "." ) )
        {
            return Calamares::JobResult::error(
                tr( "Directory Error" ),
                tr( "Could not create /etc/systemd directory in target root." ) );
        }
    }

    QString confPath = systemdDir.filePath( QStringLiteral( "zram-generator.conf" ) );
    QFile confFile( confPath );
    if ( !confFile.open( QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate ) )
    {
        return Calamares::JobResult::error(
            tr( "File Error" ),
            tr( "Could not write zram-generator.conf to target system." ) );
    }

    QTextStream out( &confFile );
    out << "# Configuration generated automatically by Parch Linux Calamares installer\n";
    out << "# Enabled because no on-disk swap partition or file was configured.\n\n";
    out << "[zram0]\n";
    out << "zram-size = " << m_size << "\n";
    out << "compression-algorithm = " << m_algorithm << "\n";
    out << "swap-priority = 100\n";
    confFile.close();

    cDebug() << "zramcfg: Successfully created" << confPath << "with size:" << m_size << "and algo:" << m_algorithm;

    return Calamares::JobResult::ok();
}

CALAMARES_PLUGIN_FACTORY_DEFINITION( ZramCfgJobFactory, registerPlugin< ZramCfgJob >(); )
