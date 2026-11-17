/* === This file is part of Calamares - <https://calamares.io> ===
 *
 *   SPDX-FileCopyrightText: 2026 Parch Linux
 *   SPDX-License-Identifier: GPL-3.0-or-later
 *
 *   Calamares is Free Software: see the License-Identifier above.
 *
 */

#include "Config.h"

#include "GlobalStorage.h"
#include "JobQueue.h"
#include "utils/Logger.h"
#include "utils/Variant.h"

#include <QVariantMap>

static const char gsSettingsKey[] = "parchSettings";

Config::Config( QObject* parent )
    : QObject( parent )
{
}

void
Config::setConfigurationMap( const QVariantMap& configurationMap )
{
    bool defaultsOk = false;
    const QVariantMap defaults = Calamares::getSubMap( configurationMap, "defaults", defaultsOk );

    setMigrationEnabled( Calamares::getBool( defaults, "migration", true ) );

    // Only accept the known RTC modes; anything else falls back to auto-detection
    const QString rtc = Calamares::getString( defaults, "windowsRtc", QStringLiteral( "auto" ) ).trimmed().toLower();
    if ( rtc == QStringLiteral( "auto" ) || rtc == QStringLiteral( "localtime" ) || rtc == QStringLiteral( "utc" ) )
    {
        setRtcMode( rtc );
    }
    else if ( !rtc.isEmpty() )
    {
        cWarning() << "parchsettings: unknown windowsRtc mode" << rtc << "- using 'auto'.";
    }

    setHidpiEnabled( Calamares::getBool( defaults, "hidpi", true ) );
    setBatteryGuardEnabled( Calamares::getBool( defaults, "batteryGuard", true ) );
    setChargeLimit( static_cast< int >( Calamares::getInteger( defaults, "chargeLimit", 80 ) ) );
    setZramEnabled( Calamares::getBool( defaults, "zram", true ) );
}

void
Config::commitGlobalStorage() const
{
    auto* jq = Calamares::JobQueue::instance();
    if ( !jq )
    {
        return;
    }
    Calamares::GlobalStorage* gs = jq->globalStorage();
    if ( !gs )
    {
        return;
    }

    // Update the existing map (if any) so keys this Config does not
    // manage are preserved.
    QVariantMap settings = gs->value( gsSettingsKey ).toMap();
    settings.insert( QStringLiteral( "migration" ), m_migrationEnabled );
    settings.insert( QStringLiteral( "windowsRtc" ), m_rtcMode );
    settings.insert( QStringLiteral( "hidpi" ), m_hidpiEnabled );
    settings.insert( QStringLiteral( "batteryGuard" ), m_batteryGuardEnabled );
    settings.insert( QStringLiteral( "chargeLimit" ), m_chargeLimit );
    settings.insert( QStringLiteral( "zram" ), m_zramEnabled );
    gs->insert( gsSettingsKey, settings );
}

void
Config::finalizeGlobalStorage() const
{
    commitGlobalStorage();
}

void
Config::setMigrationEnabled( bool enabled )
{
    if ( m_migrationEnabled == enabled )
    {
        return;
    }
    m_migrationEnabled = enabled;
    commitGlobalStorage();
    emit migrationEnabledChanged( enabled );
}

void
Config::setRtcMode( const QString& mode )
{
    QString normalized = mode.trimmed().toLower();
    if ( normalized != QStringLiteral( "auto" ) && normalized != QStringLiteral( "localtime" )
         && normalized != QStringLiteral( "utc" ) )
    {
        normalized = QStringLiteral( "auto" );
    }
    if ( m_rtcMode == normalized )
    {
        return;
    }
    m_rtcMode = normalized;
    commitGlobalStorage();
    emit rtcModeChanged( normalized );
}

void
Config::setHidpiEnabled( bool enabled )
{
    if ( m_hidpiEnabled == enabled )
    {
        return;
    }
    m_hidpiEnabled = enabled;
    commitGlobalStorage();
    emit hidpiEnabledChanged( enabled );
}

void
Config::setBatteryGuardEnabled( bool enabled )
{
    if ( m_batteryGuardEnabled == enabled )
    {
        return;
    }
    m_batteryGuardEnabled = enabled;
    commitGlobalStorage();
    emit batteryGuardEnabledChanged( enabled );
}

void
Config::setChargeLimit( int limit )
{
    const int clamped = qBound( 50, limit, 100 );
    if ( m_chargeLimit == clamped )
    {
        return;
    }
    m_chargeLimit = clamped;
    commitGlobalStorage();
    emit chargeLimitChanged( clamped );
}

void
Config::setZramEnabled( bool enabled )
{
    if ( m_zramEnabled == enabled )
    {
        return;
    }
    m_zramEnabled = enabled;
    commitGlobalStorage();
    emit zramEnabledChanged( enabled );
}
