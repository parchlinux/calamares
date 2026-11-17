#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# === This file is part of Calamares - <https://calamares.io> ===
#
#   SPDX-FileCopyrightText: 2014-2015 Philip Müller <philm@manjaro.org>
#   SPDX-FileCopyrightText: 2014 Teo Mrnjavac <teo@kde.org>
#   SPDX-FileCopyrightText: 2017 Alf Gaida <agaida@siduction.org>
#   SPDX-FileCopyrightText: 2017-2018 Gabriel Craciunescu <crazy@frugalware.org>
#   SPDX-FileCopyrightText: 2019 Adriaan de Groot <groot@kde.org>
#   SPDX-License-Identifier: GPL-3.0-or-later
#
#   Calamares is Free Software: see the License-Identifier above.
#

import libcalamares
import os

import gettext
_ = gettext.translation("calamares-python",
                        localedir=libcalamares.utils.gettext_path(),
                        languages=libcalamares.utils.gettext_languages(),
                        fallback=True).gettext


def pretty_name():
    return _("Setting hardware clock.")


def is_windows_detected():
    """
    Checks whether a Windows installation exists on the system.
    Inspects os-prober output and migration findings.
    """
    global_storage = libcalamares.globalstorage

    if global_storage.contains("osproberLines"):
        lines = global_storage.value("osproberLines")
        if lines:
            for line in lines:
                if "windows" in str(line).lower():
                    return True

    if global_storage.contains("migrationOs"):
        migration_os = str(global_storage.value("migrationOs") or "").lower()
        if "windows" in migration_os:
            return True

    # Also inspect partition entries for Windows bootloaders or signatures
    if global_storage.contains("partitions"):
        partitions = global_storage.value("partitions") or []
        for partition in partitions:
            claimed_name = str(partition.get("claimedName", "")).lower()
            if "windows" in claimed_name:
                return True

    return False


def run():
    """
    Set hardware clock.
    If Windows dual-boot is detected, configure RTC to localtime to prevent
    clock desynchronization between Windows and Linux.
    """
    windows_present = is_windows_detected()
    if windows_present:
        libcalamares.utils.debug(
            "Windows installation detected: configuring RTC for localtime to prevent dual-boot clock drift."
        )
        clock_mode = "--localtime"
        try:
            libcalamares.utils.target_env_call(
                ["timedatectl", "set-local-rtc", "1", "--adjust-system-clock"]
            )
        except Exception as e:
            libcalamares.utils.debug(f"timedatectl set-local-rtc 1 returned: {e}")
    else:
        libcalamares.utils.debug("Configuring RTC for UTC.")
        clock_mode = "--utc"
        try:
            libcalamares.utils.target_env_call(
                ["timedatectl", "set-local-rtc", "0", "--adjust-system-clock"]
            )
        except Exception as e:
            libcalamares.utils.debug(f"timedatectl set-local-rtc 0 returned: {e}")

    hwclock_rtc = ["hwclock", "--systohc", clock_mode]
    hwclock_isa = ["hwclock", "--systohc", clock_mode, "--directisa"]
    is_broken_rtc = False
    is_broken_isa = False

    ret = libcalamares.utils.target_env_call(hwclock_rtc)
    if ret != 0:
        is_broken_rtc = True
        libcalamares.utils.debug("Hwclock returned error code {}".format(ret))
        libcalamares.utils.debug("  .. RTC method failed, trying ISA bus method.")
    else:
        libcalamares.utils.debug("Hwclock set using RTC method.")
    if is_broken_rtc:
        ret = libcalamares.utils.target_env_call(hwclock_isa)
        if ret != 0:
            is_broken_isa = True
            libcalamares.utils.debug("Hwclock returned error code {}".format(ret))
            libcalamares.utils.debug("  .. ISA bus method failed.")
        else:
            libcalamares.utils.debug("Hwclock set using ISA bus method.")
    if is_broken_rtc and is_broken_isa:
        libcalamares.utils.debug("BIOS or Kernel BUG: Setting hwclock failed.")

    # Ensure /etc/adjtime in target reflects LOCAL or UTC correctly
    root_mount_point = libcalamares.globalstorage.value("rootMountPoint")
    if root_mount_point:
        adjtime_path = os.path.join(root_mount_point, "etc/adjtime")
        if windows_present:
            adjtime_content = "0.0 0 0\n0\nLOCAL\n"
            try:
                with open(adjtime_path, "w") as f:
                    f.write(adjtime_content)
                libcalamares.utils.debug("Wrote LOCAL mode to /etc/adjtime.")
            except Exception as e:
                libcalamares.utils.debug(f"Failed to write /etc/adjtime: {e}")

    return None
