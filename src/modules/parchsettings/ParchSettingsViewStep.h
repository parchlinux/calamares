/* === This file is part of Calamares - <https://calamares.io> ===
 *
 *   SPDX-FileCopyrightText: 2026 Parch Linux
 *   SPDX-License-Identifier: GPL-3.0-or-later
 *
 *   Calamares is Free Software: see the License-Identifier above.
 *
 */

#ifndef PARCHSETTINGSVIEWSTEP_H
#define PARCHSETTINGSVIEWSTEP_H

#include "Config.h"

#include "DllMacro.h"
#include "utils/PluginFactory.h"
#include "viewpages/QmlViewStep.h"

#include <QObject>
#include <QVariant>

class PLUGINDLLEXPORT ParchSettingsViewStep : public Calamares::QmlViewStep
{
    Q_OBJECT

public:
    explicit ParchSettingsViewStep( QObject* parent = nullptr );

    QString prettyName() const override;

    bool isNextEnabled() const override;
    bool isBackEnabled() const override;

    bool isAtBeginning() const override;
    bool isAtEnd() const override;

    Calamares::JobList jobs() const override;

    void onLeave() override;

    void setConfigurationMap( const QVariantMap& configurationMap ) override;

    QObject* getConfig() override { return m_config; }

private:
    Config* m_config;
};

CALAMARES_PLUGIN_FACTORY_DECLARATION( ParchSettingsViewStepFactory )

#endif  // PARCHSETTINGSVIEWSTEP_H
