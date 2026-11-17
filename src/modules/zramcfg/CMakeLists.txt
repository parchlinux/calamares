# === This file is part of Calamares - <https://calamares.io> ===
#
#   SPDX-FileCopyrightText: 2026 Parch Linux
#   SPDX-License-Identifier: GPL-3.0-or-later
#
calamares_add_plugin(zramcfg
    TYPE job
    EXPORT_MACRO PLUGINDLLEXPORT_PRO
    SOURCES
        ZramCfgJob.cpp
    SHARED_LIB
)
