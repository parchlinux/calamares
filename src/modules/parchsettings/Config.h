/* === This file is part of Calamares - <https://calamares.io> ===
 *
 *   SPDX-FileCopyrightText: 2026 Parch Linux
 *   SPDX-License-Identifier: GPL-3.0-or-later
 *
 *   Calamares is Free Software: see the License-Identifier above.
 *
 */

#ifndef PARCHSETTINGS_CONFIG_H
#define PARCHSETTINGS_CONFIG_H

#include <QObject>
#include <QString>

/**
 * @brief Settings for the Parch install-time feature switches.
 *
 * Each switch is exposed to QML and written through to GlobalStorage
 * as the @c parchSettings map whenever it changes. The target modules
 * (migration, hwclock, systuner, zramcfg) read that map at exec time;
 * a missing map or key keeps the pre-existing behavior.
 */
class Config : public QObject
{
    Q_OBJECT

    Q_PROPERTY( bool migrationEnabled READ migrationEnabled WRITE setMigrationEnabled NOTIFY migrationEnabledChanged )
    Q_PROPERTY( QString rtcMode READ rtcMode WRITE setRtcMode NOTIFY rtcModeChanged )
    Q_PROPERTY( bool hidpiEnabled READ hidpiEnabled WRITE setHidpiEnabled NOTIFY hidpiEnabledChanged )
    Q_PROPERTY( bool batteryGuardEnabled READ batteryGuardEnabled WRITE setBatteryGuardEnabled NOTIFY
                    batteryGuardEnabledChanged )
    Q_PROPERTY( int chargeLimit READ chargeLimit WRITE setChargeLimit NOTIFY chargeLimitChanged )
    Q_PROPERTY( bool zramEnabled READ zramEnabled WRITE setZramEnabled NOTIFY zramEnabledChanged )

public:
    explicit Config( QObject* parent = nullptr );

    bool migrationEnabled() const { return m_migrationEnabled; }
    QString rtcMode() const { return m_rtcMode; }
    bool hidpiEnabled() const { return m_hidpiEnabled; }
    bool batteryGuardEnabled() const { return m_batteryGuardEnabled; }
    int chargeLimit() const { return m_chargeLimit; }
    bool zramEnabled() const { return m_zramEnabled; }

    /// Reads the `defaults` section of parchsettings.conf
    void setConfigurationMap( const QVariantMap& configurationMap );

    /// Writes the current settings into GlobalStorage under `parchSettings`
    void finalizeGlobalStorage() const;

public Q_SLOTS:
    void setMigrationEnabled( bool enabled );
    void setRtcMode( const QString& mode );
    void setHidpiEnabled( bool enabled );
    void setBatteryGuardEnabled( bool enabled );
    void setChargeLimit( int limit );
    void setZramEnabled( bool enabled );

signals:
    void migrationEnabledChanged( bool );
    void rtcModeChanged( const QString& );
    void hidpiEnabledChanged( bool );
    void batteryGuardEnabledChanged( bool );
    void chargeLimitChanged( int );
    void zramEnabledChanged( bool );

private:
    void commitGlobalStorage() const;

    bool m_migrationEnabled = true;
    QString m_rtcMode = QStringLiteral( "auto" );
    bool m_hidpiEnabled = true;
    bool m_batteryGuardEnabled = true;
    int m_chargeLimit = 80;
    bool m_zramEnabled = true;
};

#endif  // PARCHSETTINGS_CONFIG_H
