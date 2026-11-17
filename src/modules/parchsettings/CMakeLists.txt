# === This file is part of Calamares - <https://calamares.io> ===
#
#   SPDX-FileCopyrightText: 2026 Parch Linux
#   SPDX-License-Identifier: BSD-2-Clause
#
if(NOT WITH_QML)
    calamares_skip_module( "parchsettings (QML is not supported in this build)" )
    return()
endif()

calamares_add_plugin(parchsettings
    TYPE viewmodule
    EXPORT_MACRO PLUGINDLLEXPORT_PRO
    SOURCES
        Config.cpp
        ParchSettingsViewStep.cpp
    RESOURCES
        parchsettings${QT_VERSION_SUFFIX}.qrc
    SHARED_LIB
)
