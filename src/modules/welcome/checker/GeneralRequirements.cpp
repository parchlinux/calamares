/* === This file is part of Calamares - <https://calamares.io> ===
 *
 *   SPDX-FileCopyrightText: 2014-2017 Teo Mrnjavac <teo@kde.org>
 *   SPDX-FileCopyrightText: 2017-2018 2020, Adriaan de Groot <groot@kde.org>
 *   SPDX-FileCopyrightText: 2017 Gabriel Craciunescu <crazy@frugalware.org>
 *   SPDX-FileCopyrightText: 2019 Collabora Ltd <arnaud.ferraris@collabora.com>
 *   SPDX-License-Identifier: GPL-3.0-or-later
 *
 *   Calamares is Free Software: see the License-Identifier above.
 *
 */

#include "GeneralRequirements.h"

#include "CheckerContainer.h"
#include "partman_devices.h"

#include "CalamaresVersion.h"  // For development-or-not
#include "GlobalStorage.h"
#include "JobQueue.h"
#include "Settings.h"
#include "compat/Variant.h"
#include "modulesystem/Requirement.h"
#include "network/Manager.h"
#include "utils/Gui.h"
#include "utils/Logger.h"
#include "utils/Retranslator.h"
#include "utils/System.h"
#include "utils/Units.h"
#include "utils/Variant.h"
#include "widgets/WaitingWidget.h"

#include <QDBusConnection>
#include <QDBusInterface>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QGuiApplication>
#include <QScreen>

#include <unistd.h>  //geteuid

GeneralRequirements::GeneralRequirements( QObject* parent )
    : QObject( parent )
    , m_requiredStorageGiB( -1 )
    , m_requiredRamGiB( -1 )
{
}

static QSize
biggestSingleScreen()
{
    QSize s;
    for ( const auto* screen : QGuiApplication::screens() )
    {
        QSize thisScreen = screen->availableSize();
        if ( !s.isValid() || ( s.width() * s.height() < thisScreen.width() * thisScreen.height() ) )
        {
            s = thisScreen;
        }
    }
    return s;
}

/** @brief Distinguish has-not-been-checked-at-all from false.
 *
 */
struct MaybeChecked
{
    bool hasBeenChecked = false;
    bool value = false;

    MaybeChecked& operator=( bool b )
    {
        hasBeenChecked = true;
        value = b;
        return *this;
    }

    operator bool() const { return value; }
};

QDebug&
operator<<( QDebug& s, const MaybeChecked& c )
{
    if ( c.hasBeenChecked )
    {
        s << c.value;
    }
    else
    {
        s << "unchecked";
    }
    return s;
}

Calamares::RequirementsList
GeneralRequirements::checkRequirements()
{
    QSize availableSize = biggestSingleScreen();

    MaybeChecked enoughStorage;
    MaybeChecked enoughRam;
    MaybeChecked hasPower;
    MaybeChecked hasInternet;
    MaybeChecked isRoot;
    MaybeChecked secureBootDisabled;
    bool enoughScreen = availableSize.isValid() && ( availableSize.width() >= Calamares::windowMinimumWidth )
        && ( availableSize.height() >= Calamares::windowMinimumHeight );

    qint64 requiredStorageB = Calamares::GiBtoBytes( m_requiredStorageGiB );
    if ( m_entriesToCheck.contains( "storage" ) )
    {
        enoughStorage = checkEnoughStorage( requiredStorageB );
    }

    qint64 requiredRamB = Calamares::GiBtoBytes( m_requiredRamGiB );
    if ( m_entriesToCheck.contains( "ram" ) )
    {
        enoughRam = checkEnoughRam( requiredRamB );
    }

    if ( m_entriesToCheck.contains( "power" ) )
    {
        hasPower = checkHasPower();
    }

    if ( m_entriesToCheck.contains( "internet" ) )
    {
        hasInternet = checkHasInternet();
    }

    if ( m_entriesToCheck.contains( "root" ) )
    {
        isRoot = checkIsRoot();
    }

    if ( m_entriesToCheck.contains( "secureboot" ) )
    {
        secureBootDisabled = checkSecureBoot();
    }

    using TNum = Logger::DebugRow< const char*, qint64 >;
    using TR = Logger::DebugRow< const char*, MaybeChecked >;
    // clang-format off
    cDebug() << "GeneralRequirements output:"
             << TNum( "storage", requiredStorageB )
             << TR( "enoughStorage", enoughStorage )
             << TNum( "RAM", requiredRamB )
             << TR( "enoughRam", enoughRam )
             << TR( "hasPower", hasPower )
             << TR( "hasInternet", hasInternet )
             << TR( "isRoot", isRoot )
             << TR( "secureBootDisabled", secureBootDisabled );
    // clang-format on

    Calamares::RequirementsList checkEntries;
    foreach ( const QString& entry, m_entriesToCheck )
    {
        const bool required = m_entriesToRequire.contains( entry );
        if ( entry == "storage" )
        {
            checkEntries.append(
                { entry,
                  [ req = m_requiredStorageGiB ]
                  {
                      return tr( "Please ensure the system has at least %1 GiB available drive space." ).arg( req )
                          + QStringLiteral( "<br/><br/>" )
                          + tr( "Available drive space is all of the hard disks and SSDs connected to the system." );
                  },
                  [ req = m_requiredStorageGiB ]
                  { return tr( "There is not enough drive space. At least %1 GiB is required." ).arg( req ); },
                  enoughStorage,
                  required } );
        }
        else if ( entry == "ram" )
        {
            checkEntries.append(
                { entry,
                  [ req = m_requiredRamGiB ] { return tr( "has at least %1 GiB working memory" ).arg( req ); },
                  [ req = m_requiredRamGiB ] {
                      return tr( "The system does not have enough working memory. At least %1 GiB is required." )
                          .arg( req );
                  },
                  enoughRam,
                  required } );
        }
        else if ( entry == "power" )
        {
            checkEntries.append( { entry,
                                   [] { return tr( "is plugged in to a power source" ); },
                                   [ bat = m_batteryPercentage ]
                                   {
                                       if ( bat >= 0 && bat < 20 )
                                       {
                                           return tr( "The system is running on low battery (%1%). Please connect to AC power." ).arg( bat );
                                       }
                                       return tr( "The system is not plugged in to a power source." );
                                   },
                                   hasPower,
                                   required } );
        }
        else if ( entry == "secureboot" )
        {
            checkEntries.append( { entry,
                                   [] { return tr( "Secure Boot is disabled" ); },
                                   [] { return tr( "Secure Boot is enabled. Please disable Secure Boot in UEFI firmware settings before proceeding." ); },
                                   secureBootDisabled,
                                   required } );
        }
        else if ( entry == "internet" )
        {
            checkEntries.append( { entry,
                                   [] { return tr( "is connected to the Internet" ); },
                                   [] { return tr( "The system is not connected to the Internet." ); },
                                   hasInternet,
                                   required } );
        }
        else if ( entry == "root" )
        {
            checkEntries.append( { entry,
                                   [] { return tr( "is running the installer as an administrator (root)" ); },
                                   []
                                   {
                                       return Calamares::Settings::instance()->isSetupMode()
                                           ? tr( "The setup program is not running with administrator rights." )
                                           : tr( "The installer is not running with administrator rights." );
                                   },
                                   isRoot,
                                   required } );
        }
        else if ( entry == "screen" )
        {
            checkEntries.append( { entry,
                                   [] { return tr( "has a screen large enough to show the whole installer" ); },
                                   []
                                   {
                                       return Calamares::Settings::instance()->isSetupMode()
                                           ? tr( "The screen is too small to display the setup program." )
                                           : tr( "The screen is too small to display the installer." );
                                   },
                                   enoughScreen,
                                   required } );
        }
#ifdef CALAMARES_VERSION_RC
        if ( entry == "false" )
        {
            checkEntries.append( { entry,
                                   [] { return tr( "is always false" ); },
                                   [] { return tr( "The computer says no." ); },
                                   false,
                                   required } );
        }
        if ( entry == "slow-false" )
        {
            sleep( 3 );
            checkEntries.append( { entry,
                                   [] { return tr( "is always false (slowly)" ); },
                                   [] { return tr( "The computer says no (slowly)." ); },
                                   false,
                                   required } );
        }
        if ( entry == "true" )
        {
            checkEntries.append( { entry,
                                   [] { return tr( "is always true" ); },
                                   [] { return tr( "The computer says yes." ); },
                                   true,
                                   required } );
        }
        if ( entry == "slow-true" )
        {
            sleep( 3 );
            checkEntries.append( { entry,
                                   [] { return tr( "is always true (slowly)" ); },
                                   [] { return tr( "The computer says yes (slowly)." ); },
                                   true,
                                   required } );
        }
        if ( entry == "snark" )
        {
            static unsigned int snark_count = 0;
            checkEntries.append( { entry,
                                   [] { return tr( "is checked three times." ); },
                                   []
                                   {
                                       return tr( "The snark has not been checked three times.",
                                                  "The (some mythological beast) has not been checked three times." );
                                   },
                                   ++snark_count > 3,
                                   required } );
        }
#endif
    }
    return checkEntries;
}

/** @brief Loads the check-internet URLs
 *
 * There may be zero or one or more URLs specified; returns
 * @c true if the configuration is incomplete or damaged in some way.
 */
static bool
getCheckInternetUrls( const QVariantMap& configurationMap )
{
    const QString exampleUrl = QStringLiteral( "http://example.com" );

    bool incomplete = false;
    QStringList checkInternetSetting = Calamares::getStringList( configurationMap, "internetCheckUrl" );
    if ( !checkInternetSetting.isEmpty() )
    {
        QVector< QUrl > urls;
        for ( const auto& urlString : std::as_const( checkInternetSetting ) )
        {
            QUrl url( urlString.trimmed() );
            if ( url.isValid() )
            {
                urls.append( url );
            }
            else
            {
                cWarning() << "GeneralRequirements entry 'internetCheckUrl' in welcome.conf contains invalid"
                           << urlString;
            }
        }

        if ( urls.empty() )
        {
            cWarning() << "GeneralRequirements entry 'internetCheckUrl' contains no valid URLs, "
                       << "reverting to default (" << exampleUrl << ").";
            Calamares::Network::Manager::setCheckHasInternetUrl( QUrl( exampleUrl ) );
            incomplete = true;
        }
        else
        {
            Calamares::Network::Manager::setCheckHasInternetUrl( urls );
        }
    }
    else
    {
        cWarning() << "GeneralRequirements entry 'internetCheckUrl' is undefined in welcome.conf, "
                      "reverting to default ("
                   << exampleUrl << ").";
        Calamares::Network::Manager::setCheckHasInternetUrl( QUrl( exampleUrl ) );
        incomplete = true;
    }
    return incomplete;
}

void
GeneralRequirements::setConfigurationMap( const QVariantMap& configurationMap )
{
    bool incompleteConfiguration = false;

    if ( configurationMap.contains( "check" )
         && Calamares::typeOf( configurationMap.value( "check" ) ) == Calamares::ListVariantType )
    {
        m_entriesToCheck.clear();
        m_entriesToCheck.append( configurationMap.value( "check" ).toStringList() );
    }
    else
    {
        cWarning() << "GeneralRequirements entry 'check' is incomplete.";
        incompleteConfiguration = true;
    }

    if ( configurationMap.contains( "required" )
         && Calamares::typeOf( configurationMap.value( "required" ) ) == Calamares::ListVariantType )
    {
        m_entriesToRequire.clear();
        m_entriesToRequire.append( configurationMap.value( "required" ).toStringList() );
    }
    else
    {
        cWarning() << "GeneralRequirements entry 'required' is incomplete.";
        incompleteConfiguration = true;
    }

#ifdef WITHOUT_LIBPARTED
    if ( m_entriesToCheck.contains( "storage" ) || m_entriesToRequire.contains( "storage" ) )
    {
        // Warn, but also drop the required bit because otherwise installation
        // will be impossible (because the check always returns false).
        cWarning() << "GeneralRequirements checks 'storage' but libparted is disabled.";
        m_entriesToCheck.removeAll( "storage" );
        m_entriesToRequire.removeAll( "storage" );
    }
#endif

    // Help out with consistency, but don't fix
    for ( const auto& r : m_entriesToRequire )
    {
        if ( !m_entriesToCheck.contains( r ) )
        {
            cWarning() << "GeneralRequirements requires" << r << "but does not check it.";
        }
    }

    if ( configurationMap.contains( "requiredStorage" )
         && ( Calamares::typeOf( configurationMap.value( "requiredStorage" ) ) == Calamares::DoubleVariantType
              || Calamares::typeOf( configurationMap.value( "requiredStorage" ) ) == Calamares::LongLongVariantType ) )
    {
        bool ok = false;
        m_requiredStorageGiB = configurationMap.value( "requiredStorage" ).toDouble( &ok );
        if ( !ok )
        {
            cWarning() << "GeneralRequirements entry 'requiredStorage' is invalid.";
            m_requiredStorageGiB = 3.;
        }

        Calamares::JobQueue::instance()->globalStorage()->insert( "requiredStorageGiB", m_requiredStorageGiB );
    }
    else
    {
        cWarning() << "GeneralRequirements entry 'requiredStorage' is missing.";
        m_requiredStorageGiB = 3.;
        incompleteConfiguration = true;
    }

    if ( configurationMap.contains( "requiredRam" )
         && ( Calamares::typeOf( configurationMap.value( "requiredRam" ) ) == Calamares::DoubleVariantType
              || Calamares::typeOf( configurationMap.value( "requiredRam" ) ) == Calamares::LongLongVariantType ) )
    {
        bool ok = false;
        m_requiredRamGiB = configurationMap.value( "requiredRam" ).toDouble( &ok );
        if ( !ok )
        {
            cWarning() << "GeneralRequirements entry 'requiredRam' is invalid.";
            m_requiredRamGiB = 1.;
            incompleteConfiguration = true;
        }
    }
    else
    {
        cWarning() << "GeneralRequirements entry 'requiredRam' is missing.";
        m_requiredRamGiB = 1.;
        incompleteConfiguration = true;
    }

    incompleteConfiguration |= getCheckInternetUrls( configurationMap );

    if ( incompleteConfiguration )
    {
        cWarning() << "GeneralRequirements configuration map:" << Logger::DebugMap( configurationMap );
    }
}

bool
GeneralRequirements::checkEnoughStorage( qint64 requiredSpace )
{
#ifdef WITHOUT_LIBPARTED
    Q_UNUSED( requiredSpace )
    cWarning() << "GeneralRequirements is configured without libparted.";
    return false;
#else
    return check_big_enough( requiredSpace );
#endif
}

bool
GeneralRequirements::checkEnoughRam( qint64 requiredRam )
{
    // Ignore the guesstimate-factor; we get an under-estimate
    // which is probably the usable RAM for programs.
    quint64 availableRam = Calamares::System::instance()->getTotalMemoryB().first;
    return double( availableRam ) >= double( requiredRam ) * 0.95;  // cast to silence 64-bit-int conversion to double
}

bool
GeneralRequirements::checkBatteryExists()
{
    const QFileInfo basePath( "/sys/class/power_supply" );

    if ( !( basePath.exists() && basePath.isDir() ) )
    {
        return false;
    }

    QDir baseDir( basePath.absoluteFilePath() );
    const auto entries = baseDir.entryList( QDir::AllDirs | QDir::Readable | QDir::NoDotAndDotDot );
    for ( const auto& item : entries )
    {
        QFileInfo typePath( baseDir.absoluteFilePath( QString( "%1/type" ).arg( item ) ) );
        QFile typeFile( typePath.absoluteFilePath() );
        if ( typeFile.open( QIODevice::ReadOnly | QIODevice::Text ) )
        {
            if ( typeFile.readAll().startsWith( "Battery" ) )
            {
                return true;
            }
        }
    }

    return false;
}

int
GeneralRequirements::getBatteryPercentage()
{
    const QDir powerSupplyDir( QStringLiteral( "/sys/class/power_supply" ) );
    if ( !powerSupplyDir.exists() )
    {
        return -1;
    }

    const auto entries = powerSupplyDir.entryList( QDir::Dirs | QDir::NoDotAndDotDot );
    for ( const auto& name : entries )
    {
        if ( name.startsWith( QStringLiteral( "BAT" ), Qt::CaseInsensitive ) )
        {
            QFile capFile( powerSupplyDir.absoluteFilePath( name + QStringLiteral( "/capacity" ) ) );
            if ( capFile.open( QIODevice::ReadOnly | QIODevice::Text ) )
            {
                bool ok = false;
                int cap = capFile.readAll().trimmed().toInt( &ok );
                if ( ok )
                {
                    return cap;
                }
            }
        }
    }
    return -1;
}

bool
GeneralRequirements::checkHasPower()
{
    if ( !checkBatteryExists() )
    {
        return true;
    }

    cDebug() << "A battery exists, checking power status and capacity.";

    // Check sysfs AC online status
    const QDir powerSupplyDir( QStringLiteral( "/sys/class/power_supply" ) );
    bool acOnline = false;
    bool checkedAc = false;

    if ( powerSupplyDir.exists() )
    {
        const auto entries = powerSupplyDir.entryList( QDir::Dirs | QDir::NoDotAndDotDot );
        for ( const auto& name : entries )
        {
            QFileInfo typeFile( powerSupplyDir.absoluteFilePath( name + QStringLiteral( "/type" ) ) );
            QFile tf( typeFile.absoluteFilePath() );
            if ( tf.open( QIODevice::ReadOnly | QIODevice::Text ) )
            {
                QString type = QString::fromUtf8( tf.readAll() ).trimmed();
                if ( type == QStringLiteral( "Mains" ) )
                {
                    QFile onlineFile( powerSupplyDir.absoluteFilePath( name + QStringLiteral( "/online" ) ) );
                    if ( onlineFile.open( QIODevice::ReadOnly | QIODevice::Text ) )
                    {
                        checkedAc = true;
                        if ( onlineFile.readAll().trimmed() == QStringLiteral( "1" ) )
                        {
                            acOnline = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    m_batteryPercentage = getBatteryPercentage();

    if ( checkedAc )
    {
        if ( acOnline )
        {
            return true;
        }
        // If unplugged and battery is critically low (< 20%), warn user
        if ( m_batteryPercentage >= 0 && m_batteryPercentage < 20 )
        {
            cWarning() << "System is unplugged and battery is critically low:" << m_batteryPercentage << "%";
            return false;
        }
        return false;
    }

    // Fallback to UPower DBus if sysfs AC was not conclusive
    const QString UPOWER_SVC_NAME( "org.freedesktop.UPower" );
    const QString UPOWER_INTF_NAME( "org.freedesktop.UPower" );
    const QString UPOWER_PATH( "/org/freedesktop/UPower" );

    QDBusInterface upowerIntf( UPOWER_SVC_NAME, UPOWER_PATH, UPOWER_INTF_NAME, QDBusConnection::systemBus() );
    if ( upowerIntf.isValid() )
    {
        bool onBattery = upowerIntf.property( "OnBattery" ).toBool();
        if ( onBattery )
        {
            return false;
        }
    }

    return true;
}

bool
GeneralRequirements::checkSecureBoot()
{
    // If not booted in EFI mode, Secure Boot does not apply (safe to continue)
    if ( !QDir( QStringLiteral( "/sys/firmware/efi" ) ).exists() )
    {
        return true;
    }

    // Check efivars: SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
    // Format: 4 bytes attributes + 1 byte data (1 = enabled, 0 = disabled)
    QFile efivar( QStringLiteral( "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c" ) );
    if ( efivar.open( QIODevice::ReadOnly ) )
    {
        QByteArray data = efivar.readAll();
        if ( data.size() >= 5 )
        {
            const bool enabled = ( data.at( 4 ) == 1 );
            cDebug() << "Secure Boot efivar detected, enabled:" << enabled;
            return !enabled;
        }
    }

    // Legacy sysfs check: /sys/firmware/efi/vars/SecureBoot-*/data
    QDir legacyDir( QStringLiteral( "/sys/firmware/efi/vars" ) );
    if ( legacyDir.exists() )
    {
        const auto entries = legacyDir.entryList( QStringList() << QStringLiteral( "SecureBoot-*" ), QDir::Dirs );
        for ( const auto& entry : entries )
        {
            QFile dataFile( legacyDir.absoluteFilePath( entry + QStringLiteral( "/data" ) ) );
            if ( dataFile.open( QIODevice::ReadOnly ) )
            {
                QByteArray data = dataFile.readAll();
                if ( !data.isEmpty() )
                {
                    const bool enabled = ( data.at( 0 ) == 1 );
                    cDebug() << "Secure Boot legacy var detected, enabled:" << enabled;
                    return !enabled;
                }
            }
        }
    }

    return true;
}

bool
GeneralRequirements::checkHasInternet()
{
    Calamares::Network::Manager nam;
    bool hasInternet = nam.checkHasInternet();
    Calamares::JobQueue::instance()->globalStorage()->insert( "hasInternet", hasInternet );
    return hasInternet;
}

bool
GeneralRequirements::checkIsRoot()
{
    return !geteuid();
}
