/* === This file is part of Calamares - <https://calamares.io> ===
 *
 *   SPDX-FileCopyrightText: 2026 Parch Linux
 *   SPDX-License-Identifier: GPL-3.0-or-later
 *
 */

#ifndef ZRAMCFGJOB_H
#define ZRAMCFGJOB_H

#include "CppJob.h"
#include "DllMacro.h"
#include "utils/PluginFactory.h"

#include <QObject>
#include <QVariantMap>

class PLUGINDLLEXPORT ZramCfgJob : public Calamares::CppJob
{
    Q_OBJECT

public:
    explicit ZramCfgJob( QObject* parent = nullptr );
    ~ZramCfgJob() override;

    QString prettyName() const override;

    Calamares::JobResult exec() override;

    void setConfigurationMap( const QVariantMap& configurationMap ) override;

private:
    QString m_algorithm;
    QString m_size;
};

CALAMARES_PLUGIN_FACTORY_DECLARATION( ZramCfgJobFactory )

#endif  // ZRAMCFGJOB_H
