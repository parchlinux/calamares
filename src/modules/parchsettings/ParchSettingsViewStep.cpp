/* === This file is part of Calamares - <https://calamares.io> ===
 *
 *   SPDX-FileCopyrightText: 2026 Parch Linux
 *   SPDX-License-Identifier: GPL-3.0-or-later
 *
 *   Calamares is Free Software: see the License-Identifier above.
 *
 */

#include "ParchSettingsViewStep.h"

#include "utils/Logger.h"

CALAMARES_PLUGIN_FACTORY_DEFINITION( ParchSettingsViewStepFactory, registerPlugin< ParchSettingsViewStep >(); )

ParchSettingsViewStep::ParchSettingsViewStep( QObject* parent )
    : Calamares::QmlViewStep( parent )
    , m_config( new Config( this ) )
{
    emit nextStatusChanged( true );
}

QString
ParchSettingsViewStep::prettyName() const
{
    return tr( "Parch Settings" );
}

bool
ParchSettingsViewStep::isNextEnabled() const
{
    return true;
}

bool
ParchSettingsViewStep::isBackEnabled() const
{
    return true;
}

bool
ParchSettingsViewStep::isAtBeginning() const
{
    return true;
}

bool
ParchSettingsViewStep::isAtEnd() const
{
    return true;
}

Calamares::JobList
ParchSettingsViewStep::jobs() const
{
    // Pure settings page: switches write GlobalStorage directly, no jobs
    return {};
}

void
ParchSettingsViewStep::onLeave()
{
    m_config->finalizeGlobalStorage();
    Calamares::QmlViewStep::onLeave();
}

void
ParchSettingsViewStep::setConfigurationMap( const QVariantMap& configurationMap )
{
    m_config->setConfigurationMap( configurationMap );
    Calamares::QmlViewStep::setConfigurationMap( configurationMap );  // call parent implementation last
}
