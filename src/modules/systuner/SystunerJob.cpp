/* === This file is part of Calamares - <https://calamares.io> ===
 *
 *   SPDX-FileCopyrightText: 2026 Parch Linux
 *   SPDX-License-Identifier: GPL-3.0-or-later
 *
 */

#include "SystunerJob.h"
#include "systuner.h"

#include "GlobalStorage.h"
#include "JobQueue.h"
#include "utils/Logger.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QGuiApplication>
#include <QScreen>
#include <QTextStream>
#include <QVariantMap>

SystunerJob::SystunerJob( QObject* parent )
    : Calamares::CppJob( parent )
    , m_profile( QStringLiteral( "auto" ) )
    , m_hidpiAutoscale( true )
    , m_batteryLongevity( true )
    , m_batteryChargeLimit( 80 )
{
}

SystunerJob::~SystunerJob()
{
}

QString
SystunerJob::prettyName() const
{
    return tr( "Optimizing system responsiveness, display scaling, and hardware parameters..." );
}

void
SystunerJob::setConfigurationMap( const QVariantMap& configurationMap )
{
    if ( configurationMap.contains( "profile" ) )
    {
        m_profile = configurationMap.value( "profile" ).toString().trimmed().toLower();
    }
    if ( configurationMap.contains( "hidpi_autoscale" ) )
    {
        m_hidpiAutoscale = configurationMap.value( "hidpi_autoscale" ).toBool();
    }
    if ( configurationMap.contains( "battery_longevity" ) )
    {
        m_batteryLongevity = configurationMap.value( "battery_longevity" ).toBool();
    }
    if ( configurationMap.contains( "battery_charge_limit" ) )
    {
        m_batteryChargeLimit = configurationMap.value( "battery_charge_limit" ).toInt();
        if ( m_batteryChargeLimit < 50 || m_batteryChargeLimit > 100 )
        {
            m_batteryChargeLimit = 80;
        }
    }
}

Calamares::JobResult
SystunerJob::exec()
{
    Calamares::GlobalStorage* gs = Calamares::JobQueue::instance()->globalStorage();
    if ( !gs || !gs->contains( "rootMountPoint" ) )
    {
        cWarning() << "Systuner: No *rootMountPoint* defined.";
        return Calamares::JobResult::internalError(
            tr( "Configuration Error" ),
            tr( "No root mount point is set for Systuner." ),
            Calamares::JobResult::InvalidConfiguration );
    }

    QString root = gs->value( "rootMountPoint" ).toString();

    // The configuration map is frozen at module-load time, so the runtime
    // overrides chosen on the Parch Settings page are applied here.
    const QVariantMap parchSettings = gs->value( "parchSettings" ).toMap();
    if ( parchSettings.contains( "hidpi" ) )
    {
        m_hidpiAutoscale = parchSettings.value( "hidpi" ).toBool();
        cDebug() << "Systuner: hidpi autoscale override from Parch Settings:" << m_hidpiAutoscale;
    }
    if ( parchSettings.contains( "batteryGuard" ) )
    {
        m_batteryLongevity = parchSettings.value( "batteryGuard" ).toBool();
        cDebug() << "Systuner: battery longevity override from Parch Settings:" << m_batteryLongevity;
    }
    if ( parchSettings.contains( "chargeLimit" ) )
    {
        const int limit = parchSettings.value( "chargeLimit" ).toInt();
        if ( limit >= 50 && limit <= 100 )
        {
            m_batteryChargeLimit = limit;
            cDebug() << "Systuner: battery charge limit override from Parch Settings:" << limit;
        }
        else
        {
            cWarning() << "Systuner: Ignoring out-of-range charge limit from Parch Settings:" << limit;
        }
    }

    systuner_sysinfo_t sysinfo;
    int rc = systuner_collect_sysinfo( &sysinfo );
    if ( rc != 0 )
    {
        cWarning() << "Systuner: Failed to collect sysinfo, error code:" << rc;
    }

    if ( QFile::exists( root + QStringLiteral( "/etc/systemd/zram-generator.conf" ) ) )
    {
        sysinfo.has_zram = true;
        cDebug() << "Systuner: Detected zram-generator configuration in target system.";
    }

    systuner_profile_t profile = SYSTUNER_PROFILE_DESKTOP;
    if ( m_profile == QStringLiteral( "auto" ) || m_profile.isEmpty() )
    {
        if ( sysinfo.is_battery_powered )
        {
            profile = SYSTUNER_PROFILE_LAPTOP;
        }
        else if ( sysinfo.total_ram_bytes > 0 && sysinfo.total_ram_bytes <= ( 4ULL * 1024 * 1024 * 1024 ) )
        {
            profile = SYSTUNER_PROFILE_LOW_MEM;
        }
        else
        {
            profile = SYSTUNER_PROFILE_DESKTOP;
        }
    }
    else
    {
        if ( !systuner_parse_profile( m_profile.toUtf8().constData(), &profile ) )
        {
            cWarning() << "Systuner: Unknown profile" << m_profile << "- falling back to desktop.";
            profile = SYSTUNER_PROFILE_DESKTOP;
        }
    }

    systuner_config_t config;
    rc = systuner_generate_config( &sysinfo, profile, &config );
    if ( rc != 0 )
    {
        return Calamares::JobResult::error(
            tr( "Systuner Optimization Failed" ),
            tr( "Failed to generate optimal kernel configuration." ) );
    }

    QDir sysctlDir( root + QStringLiteral( "/etc/sysctl.d" ) );
    if ( !sysctlDir.exists() )
    {
        if ( !sysctlDir.mkpath( "." ) )
        {
            return Calamares::JobResult::error(
                tr( "Systuner Directory Error" ),
                tr( "Could not create /etc/sysctl.d in target root." ) );
        }
    }

    QString targetConf = sysctlDir.filePath( QStringLiteral( "99-systuner.conf" ) );
    rc = systuner_write_file( &config, targetConf.toUtf8().constData() );
    if ( rc != 0 )
    {
        return Calamares::JobResult::error(
            tr( "Systuner File Error" ),
            tr( "Failed to write 99-systuner.conf to target system." ) );
    }

    cDebug() << "Systuner successfully applied profile:" << systuner_profile_to_string( profile )
             << "with" << config.param_count << "parameters written to" << targetConf;

    // Feature 2: HiDPI / Retina Auto-Scaling
    configureHiDPI( root );

    // Feature 3: Battery Longevity Guard (80% charge threshold)
    configureBatteryLongevity( root, sysinfo );

    return Calamares::JobResult::ok();
}

void
SystunerJob::configureBatteryLongevity( const QString& root, const systuner_sysinfo_t& sysinfo )
{
    if ( !m_batteryLongevity )
    {
        return;
    }

    bool hasBattery = sysinfo.is_battery_powered;
    if ( !hasBattery )
    {
        QDir powerSupply( QStringLiteral( "/sys/class/power_supply" ) );
        if ( powerSupply.exists() )
        {
            const auto entries = powerSupply.entryList( QDir::Dirs | QDir::NoDotAndDotDot );
            for ( const QString& entry : entries )
            {
                if ( entry.startsWith( QStringLiteral( "BAT" ), Qt::CaseInsensitive ) )
                {
                    hasBattery = true;
                    break;
                }
            }
        }
    }

    if ( !hasBattery )
    {
        cDebug() << "Systuner: No battery hardware detected, skipping battery longevity guard.";
        return;
    }

    cDebug() << "Systuner: Battery detected. Setting up" << m_batteryChargeLimit << "% charge threshold longevity guard.";
    QDir tmpfilesDir( root + QStringLiteral( "/etc/tmpfiles.d" ) );
    if ( !tmpfilesDir.exists() )
    {
        tmpfilesDir.mkpath( QStringLiteral( "." ) );
    }

    QString confPath = tmpfilesDir.filePath( QStringLiteral( "parch-battery-longevity.conf" ) );
    QFile file( confPath );
    if ( file.open( QIODevice::WriteOnly | QIODevice::Text ) )
    {
        QTextStream out( &file );
        out << "# Parch Linux Battery Longevity & Health Guard\n"
            << "# Automatically limits maximum battery charge level to " << m_batteryChargeLimit << "% on supported laptops\n"
            << "w- /sys/class/power_supply/BAT*/charge_control_end_threshold - - - - " << m_batteryChargeLimit << "\n"
            << "w- /sys/class/power_supply/BAT*/charge_control_limit_max - - - - " << m_batteryChargeLimit << "\n"
            << "w- /sys/bus/platform/drivers/ideapad_acpi/VPC2004:00/conservation_mode - - - - 1\n"
            << "w- /sys/devices/platform/samsung/battery_life_extender - - - - 1\n"
            << "w- /sys/devices/platform/lg-laptop/battery_care_limit - - - - " << m_batteryChargeLimit << "\n";
        file.close();
        cDebug() << "Systuner: Battery longevity configuration written to" << confPath;
    }
    else
    {
        cWarning() << "Systuner: Could not write battery longevity configuration to" << confPath;
    }
}

void
SystunerJob::configureHiDPI( const QString& root )
{
    if ( !m_hidpiAutoscale )
    {
        return;
    }

    qreal scaleFactor = 1.0;
    qreal dpi = 96.0;
    int screenWidth = 0;
    int screenHeight = 0;

    QScreen* screen = QGuiApplication::primaryScreen();
    if ( screen )
    {
        dpi = screen->logicalDotsPerInch();
        qreal dpr = screen->devicePixelRatio();
        QSize geom = screen->size();
        screenWidth = geom.width();
        screenHeight = geom.height();
        QSizeF physMm = screen->physicalSize();

        cDebug() << "Systuner: Display metrics - DPI:" << dpi << "DPR:" << dpr
                 << "Resolution:" << screenWidth << "x" << screenHeight
                 << "Physical size (mm):" << physMm.width() << "x" << physMm.height();

        if ( dpr >= 1.75 || dpi >= 180.0 || ( screenWidth >= 3840 && physMm.width() > 0 && physMm.width() <= 750 ) )
        {
            scaleFactor = 2.0;
        }
        else if ( dpr >= 1.25 || dpi >= 135.0 || ( screenWidth >= 2560 && physMm.width() > 0 && physMm.width() <= 400 ) )
        {
            scaleFactor = 1.5;
        }
        else if ( dpr > 1.0 )
        {
            scaleFactor = dpr;
        }
    }

    if ( scaleFactor <= 1.0 )
    {
        cDebug() << "Systuner: Standard display detected (scale 1.0), no scaling adjustments needed.";
        return;
    }

    cDebug() << "Systuner: HiDPI display detected! Applying auto-scale factor:" << scaleFactor;

    // 1. SDDM HiDPI configuration
    QDir sddmDir( root + QStringLiteral( "/etc/sddm.conf.d" ) );
    if ( !sddmDir.exists() )
    {
        sddmDir.mkpath( QStringLiteral( "." ) );
    }
    QString sddmConf = sddmDir.filePath( QStringLiteral( "10-hidpi.conf" ) );
    QFile sddmFile( sddmConf );
    if ( sddmFile.open( QIODevice::WriteOnly | QIODevice::Text ) )
    {
        QTextStream out( &sddmFile );
        out << "[General]\n"
            << "EnableHiDPI=true\n\n"
            << "[Wayland]\n"
            << "EnableHiDPI=true\n";
        sddmFile.close();
        cDebug() << "Systuner: SDDM HiDPI config written to" << sddmConf;
    }

    // 2. /etc/environment for Qt/GDK global scaling
    QString envPath = root + QStringLiteral( "/etc/environment" );
    QFile envFile( envPath );
    QString envContent;
    if ( envFile.open( QIODevice::ReadOnly | QIODevice::Text ) )
    {
        envContent = QString::fromUtf8( envFile.readAll() );
        envFile.close();
    }
    bool modifiedEnv = false;
    if ( !envContent.contains( QStringLiteral( "QT_ENABLE_HIGHDPI_SCALING" ) ) )
    {
        envContent += QStringLiteral( "\nQT_ENABLE_HIGHDPI_SCALING=1\n" );
        modifiedEnv = true;
    }
    if ( !envContent.contains( QStringLiteral( "QT_AUTO_SCREEN_SCALE_FACTOR" ) ) )
    {
        envContent += QStringLiteral( "QT_AUTO_SCREEN_SCALE_FACTOR=1\n" );
        modifiedEnv = true;
    }
    if ( scaleFactor >= 2.0 && !envContent.contains( QStringLiteral( "GDK_SCALE" ) ) )
    {
        envContent += QStringLiteral( "GDK_SCALE=2\n" );
        modifiedEnv = true;
    }
    if ( modifiedEnv )
    {
        if ( envFile.open( QIODevice::WriteOnly | QIODevice::Text ) )
        {
            envFile.write( envContent.toUtf8() );
            envFile.close();
            cDebug() << "Systuner: Added HiDPI scaling flags to /etc/environment";
        }
    }

    // 3. KDE Plasma kdeglobals
    QDir kdeXdgDir( root + QStringLiteral( "/etc/xdg" ) );
    if ( !kdeXdgDir.exists() )
    {
        kdeXdgDir.mkpath( QStringLiteral( "." ) );
    }
    QString kdeGlobalsPath = kdeXdgDir.filePath( QStringLiteral( "kdeglobals" ) );
    QFile kdeFile( kdeGlobalsPath );
    QString kdeContent;
    if ( kdeFile.open( QIODevice::ReadOnly | QIODevice::Text ) )
    {
        kdeContent = QString::fromUtf8( kdeFile.readAll() );
        kdeFile.close();
    }
    if ( !kdeContent.contains( QStringLiteral( "[KScreen]" ) ) )
    {
        kdeContent += QString( "\n[KScreen]\nScaleFactor=%1\n" ).arg( QString::number( scaleFactor, 'f', 1 ) );
        if ( kdeFile.open( QIODevice::WriteOnly | QIODevice::Text ) )
        {
            kdeFile.write( kdeContent.toUtf8() );
            kdeFile.close();
            cDebug() << "Systuner: Configured KDE Plasma ScaleFactor =" << scaleFactor << "in" << kdeGlobalsPath;
        }
    }
}

CALAMARES_PLUGIN_FACTORY_DEFINITION( SystunerJobFactory, registerPlugin< SystunerJob >(); )
