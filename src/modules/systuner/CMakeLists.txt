# === This file is part of Calamares - <https://calamares.io> ===
#
#   SPDX-FileCopyrightText: 2026 Parch Linux
#   SPDX-License-Identifier: GPL-3.0-or-later
#
calamares_add_plugin(systuner
    TYPE job
    EXPORT_MACRO PLUGINDLLEXPORT_PRO
    SOURCES
        SystunerJob.cpp
        sysinfo.c
        sysctl.c
        tuner.c
    SHARED_LIB
)

target_link_libraries(calamares_job_systuner PRIVATE ${qtname}::Gui)
