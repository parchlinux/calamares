/* === This file is part of Calamares - <https://calamares.io> ===
 *
 *   SPDX-FileCopyrightText: 2026 Parch Linux
 *   SPDX-License-Identifier: GPL-3.0-or-later
 *
 */

#ifndef SYSTUNERJOB_H
#define SYSTUNERJOB_H

#include "CppJob.h"
#include "DllMacro.h"
#include "utils/PluginFactory.h"

#include <QObject>
#include <QVariantMap>

class PLUGINDLLEXPORT SystunerJob : public Calamares::CppJob
{
    Q_OBJECT

public:
    explicit SystunerJob( QObject* parent = nullptr );
    ~SystunerJob() override;

    QString prettyName() const override;

    Calamares::JobResult exec() override;

    void setConfigurationMap( const QVariantMap& configurationMap ) override;

private:
    QString m_profile;
};

CALAMARES_PLUGIN_FACTORY_DECLARATION( SystunerJobFactory )

#endif  // SYSTUNERJOB_H
