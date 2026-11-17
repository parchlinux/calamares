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
#include <QFileInfo>

SystunerJob::SystunerJob( QObject* parent )
    : Calamares::CppJob( parent )
    , m_profile( QStringLiteral( "auto" ) )
{
}

SystunerJob::~SystunerJob()
{
}

QString
SystunerJob::prettyName() const
{
    return tr( "Optimizing system responsiveness and kernel parameters..." );
}

void
SystunerJob::setConfigurationMap( const QVariantMap& configurationMap )
{
    if ( configurationMap.contains( "profile" ) )
    {
        m_profile = configurationMap.value( "profile" ).toString().trimmed().toLower();
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

    systuner_sysinfo_t sysinfo;
    int rc = systuner_collect_sysinfo( &sysinfo );
    if ( rc != 0 )
    {
        cWarning() << "Systuner: Failed to collect sysinfo, error code:" << rc;
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

    return Calamares::JobResult::ok();
}

CALAMARES_PLUGIN_FACTORY_DEFINITION( SystunerJobFactory, registerPlugin< SystunerJob >(); )
