#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# === This file is part of Calamares - <https://calamares.io> ===
#
#   SPDX-FileCopyrightText: 2014 Philip Müller <philm@manjaro.org>
#   SPDX-FileCopyrightText: 2014 Teo Mrnjavac <teo@kde.org>
#   SPDX-FileCopyrightText: 2017 Alf Gaida <agaida@siduction.org>
#   SPDX-FileCopyrightText: 2019 Adriaan de Groot <groot@kde.org>
#   SPDX-FileCopyrightText: 2021 Anke boersma <demm@koasx.us>
#   SPDX-License-Identifier: GPL-3.0-or-later
#
#   Calamares is Free Software: see the License-Identifier above.
#

import os
import glob
import shutil

import libcalamares

import gettext
_ = gettext.translation("calamares-python",
                        localedir=libcalamares.utils.gettext_path(),
                        languages=libcalamares.utils.gettext_languages(),
                        fallback=True).gettext


def pretty_name():
    return _("Saving network configuration.")


def get_live_user():
    """
    Gets the "live user" login. This might be "live", or "nitrux",
    or something similar: it is the login name used *right now*,
    and network configurations saved for that user, should be applied
    also for the installed user (which probably has a different name).
    """
    # getlogin() is a thin-wrapper, and depends on getlogin(3),
    # which reads utmp -- and utmp isn't always set up right.
    try:
        return os.getlogin()
    except OSError:
        pass
    # getpass will return the **current** user, which is generally root.
    # That isn't very useful, because the network settings have been
    # made outside of Calamares-running-as-root, as a different user.
    #
    # If Calamares is running as non-root, though, this is fine.
    import getpass
    name = getpass.getuser()
    if name != "root":
        return name

    # TODO: other mechanisms, e.g. guessing that "live" is the name
    # TODO: support a what-is-the-live-user setting
    return None


def replace_username(nm_config_filename, live_user, target_user):
    """
    Ensure the NetworkManager connection is usable by the target user.
    If permissions are restricted to a user, update it to target_user,
    or make it available system-wide.
    """
    if not os.path.exists(nm_config_filename):
        return

    try:
        with open(nm_config_filename, "r", encoding="UTF-8") as network_conf:
            lines = network_conf.readlines()

        new_lines = []
        for line in lines:
            if line.strip().startswith("permissions="):
                if target_user:
                    new_lines.append(f"permissions=user:{target_user}:;\n")
                else:
                    # No user specified, make connection available system-wide
                    continue
            else:
                new_lines.append(line)

        with open(nm_config_filename, "w", encoding="UTF-8") as network_conf:
            network_conf.writelines(new_lines)
    except Exception as e:
        libcalamares.utils.warning(f"networkcfg: Error updating permissions in {nm_config_filename}: {e}")


def path_pair(root_mount_point, relative_path):
    """
    Returns /relative_path and the relative path in the target system.
    """
    return ("/" + relative_path, os.path.join(root_mount_point, relative_path))


def run():
    """
    Setup network configuration
    """
    root_mount_point = libcalamares.globalstorage.value("rootMountPoint")
    user = libcalamares.globalstorage.value("username")
    live_user = get_live_user()

    if root_mount_point is None:
        libcalamares.utils.warning("rootMountPoint is empty, {!s}".format(root_mount_point))
        return (_("Configuration Error"),
                _("No root mount point is given for <pre>{!s}</pre> to use." ).format("networkcfg"))

    source_nm, target_nm = path_pair(root_mount_point, "etc/NetworkManager/system-connections/")

    # Carry over NetworkManager Wi-Fi and network connections from Live ISO
    if os.path.exists(source_nm):
        os.makedirs(target_nm, mode=0o700, exist_ok=True)
        for network in os.listdir(source_nm):
            # Skip LTSP live
            if network == "LTSP":
                continue

            source_network = os.path.join(source_nm, network)
            target_network = os.path.join(target_nm, network)

            if os.path.exists(target_network):
                continue

            try:
                shutil.copy2(source_network, target_network, follow_symlinks=False)
                replace_username(target_network, live_user, user)
                # NetworkManager requires strictly 0600 root:root permissions on keyfiles
                os.chmod(target_network, 0o600)
                os.chown(target_network, 0, 0)
                libcalamares.utils.debug(f"networkcfg: Transferred connection '{network}' to target system.")
            except Exception as e:
                libcalamares.utils.debug(f"networkcfg: Could not transfer '{network}': {e}")

    # Also carry over iwd Wi-Fi credentials if present
    source_iwd = "/var/lib/iwd"
    target_iwd = os.path.join(root_mount_point, "var/lib/iwd")
    if os.path.exists(source_iwd):
        psk_files = glob.glob(os.path.join(source_iwd, "*.psk"))
        if psk_files:
            try:
                os.makedirs(target_iwd, mode=0o700, exist_ok=True)
                for psk in psk_files:
                    target_psk = os.path.join(target_iwd, os.path.basename(psk))
                    if not os.path.exists(target_psk):
                        shutil.copy2(psk, target_psk)
                        os.chmod(target_psk, 0o600)
                        os.chown(target_psk, 0, 0)
                        libcalamares.utils.debug(f"networkcfg: Transferred iwd credential '{os.path.basename(psk)}'.")
            except Exception as err:
                libcalamares.utils.debug(f"networkcfg: Failed to transfer iwd PSK credentials: {err}")

    # Also install netplan files
    source_netplan = "/etc/netplan"
    root_mount_point = libcalamares.globalstorage.value("rootMountPoint")
    target_netplan = os.path.join(root_mount_point, source_netplan.lstrip('/'))

    if os.path.exists(source_netplan) and os.path.exists(target_netplan):
        # Set NetworkManager to be the default renderer if Netplan is installed
        # TODO: We might rather do that inside the network-manager package, see:
        # https://bugs.launchpad.net/ubuntu/+source/ubuntu-settings/+bug/2020110
        default_renderer = os.path.join(root_mount_point, "usr/lib/netplan",
                                        "00-network-manager-all.yaml")
        if not os.path.exists(default_renderer):
            renderer_file = os.path.join(target_netplan,
                                         "01-network-manager-all.yaml")
            nm_renderer = """# This file was written by calamares.
# Let NetworkManager manage all devices on this system.
# For more information, see netplan(5).
network:
  version: 2
  renderer: NetworkManager
"""
            with open(renderer_file, 'w') as f:
                f.writelines(nm_renderer)
                os.chmod(f.fileno(), 0o600)

        # Copy existing Netplan configuration
        for cfg in glob.glob(os.path.join(source_netplan, "*.yaml")):
            source_cfg = os.path.join(source_netplan, cfg)
            target_cfg = os.path.join(target_netplan, os.path.basename(cfg))

            if os.path.exists(target_cfg):
                continue

            shutil.copy(source_cfg, target_cfg)

    # We need to overwrite the default resolv.conf in the chroot.
    source_resolv, target_resolv = path_pair(root_mount_point, "etc/resolv.conf")
    if source_resolv != target_resolv and os.path.exists(source_resolv):
        try:
            os.remove(target_resolv)
        except Exception as err:
            libcalamares.utils.debug(
                "Couldn't remove {}: {}".format(target_resolv, err)
                )

        try:
            shutil.copy(source_resolv, target_resolv, follow_symlinks=False)
        except Exception as err:
            libcalamares.utils.debug(
                "Can't copy resolv.conf from {}: {}".format(source_resolv, err)
                )

    return None
