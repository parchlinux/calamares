#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later

import fileinput
import logging
import os
import shutil
import subprocess
import stat
import tempfile
from contextlib import contextmanager

import libcalamares

from libcalamares.utils import check_target_env_call, check_target_env_output, gettext_path, gettext_languages
from libcalamares.utils import host_env_process_output

_ = libcalamares.utils.gettext_translation("calamares-python",
                                           localedir=gettext_path(),
                                           languages=gettext_languages(),
                                           fallback=True).gettext

logger = logging.getLogger(__name__)


def pretty_name():
    return _("Configure Windows Boot Entries")


# --- Error Classes ---
class WindowsBootEntryError(Exception):
    """Base exception for Windows boot entry errors"""
    pass


class MissingGlobalStorageError(WindowsBootEntryError):
    """Raised when required global storage keys are missing"""
    pass


class BootloaderConfigError(WindowsBootEntryError):
    """Raised for bootloader configuration errors"""
    pass


# --- Helper Functions ---
@contextmanager
def mounted(device, mountpoint):
    """Context manager for temporary mounting"""
    try:
        host_env_process_output(["mount", device, mountpoint])
        yield mountpoint
    except subprocess.CalledProcessError as e:
        logger.error("Failed to mount %s at %s: %s", device, mountpoint, e)
        raise BootloaderConfigError(f"Mount failed: {e}") from e
    finally:
        try:
            host_env_process_output(["umount", mountpoint])
        except subprocess.CalledProcessError as e:
            logger.warning("Failed to unmount %s: %s", mountpoint, e)


def validate_global_storage():
    """Validate required global storage values exist"""
    required_keys = [
        "rootMountPoint",
        "partitions",
        "efiSystemPartition",
        "firmwareType"
    ]
    missing = [k for k in required_keys if not libcalamares.globalstorage.contains(k)]
    if missing:
        raise MissingGlobalStorageError(
            f"Missing required global storage keys: {', '.join(missing)}"
        )


# --- Bootloader Handlers ---
def handle_systemd_boot(efi_directory):
    """Handle Windows entries for systemd-boot"""
    root_path = libcalamares.globalstorage.value("rootMountPoint")
    install_efi = os.path.join(root_path, efi_directory.lstrip('/'))

    # Get all EFI partitions from partition module
    esp_list = libcalamares.globalstorage.value("espList", [])
    partitions = libcalamares.globalstorage.value("partitions")

    for part in partitions:
        try:
            if part["device"] in esp_list and part["mountPoint"] != efi_directory:
                logger.debug("Found foreign ESP at %s", part["device"])

                with tempfile.TemporaryDirectory() as temp_mount:
                    try:
                        with mounted(part["device"].strip(), temp_mount):
                            source_dir = os.path.join(temp_mount, "EFI", "Microsoft")
                            if os.path.isdir(source_dir):
                                target_dir = os.path.join(install_efi, "EFI", "Microsoft")
                                logger.info("Copying Windows boot files from %s to %s", source_dir, target_dir)
                                shutil.copytree(source_dir, target_dir, dirs_exist_ok=True)
                    except BootloaderConfigError:
                        continue  # Already logged, continue with other partitions

        except KeyError as e:
            logger.warning("Partition missing required key: %s", e)


def handle_grub():
    """Handle Windows entries for GRUB"""
    root_path = libcalamares.globalstorage.value("rootMountPoint")
    grub_config = os.path.join(root_path, "etc/default/grub")

    # Enable os-prober temporarily
    try:
        with open(grub_config, 'r+') as f:
            content = f.read()
            f.seek(0)
            f.write(content.replace("GRUB_DISABLE_OS_PROBER=true", "#GRUB_DISABLE_OS_PROBER=false"))
            f.truncate()
    except IOError as e:
        raise BootloaderConfigError(f"Failed to modify GRUB config: {e}") from e

    # Generate GRUB config
    try:
        output = check_target_env_output(["grub-mkconfig"])
    except subprocess.CalledProcessError as e:
        raise BootloaderConfigError(f"GRUB config generation failed: {e}") from e

    # Parse Windows entries
    windows_entry = []
    in_os_prober = False
    for line in output.split('\n'):
        if "### BEGIN /etc/grub.d/30_os-prober ###" in line:
            in_os_prober = True
        elif "### END /etc/grub.d/30_os-prober ###" in line:
            break
        elif in_os_prober and "Windows" in line:
            windows_entry.append(line + '\n')

    if windows_entry:
        entry_path = os.path.join(root_path, "etc/grub.d/45_parch_windows")
        try:
            with open(entry_path, 'w') as f:
                f.write("#!/bin/sh\n")
                f.write("exec tail -n +3 $0\n\n")
                f.writelines(windows_entry)
            os.chmod(entry_path, 0o755)
        except IOError as e:
            raise BootloaderConfigError(f"Failed to write Windows GRUB entry: {e}") from e

    # Disable os-prober
    try:
        with open(grub_config, 'r+') as f:
            content = f.read()
            f.seek(0)
            f.write(content.replace("#GRUB_DISABLE_OS_PROBER=false", "GRUB_DISABLE_OS_PROBER=true"))
            f.truncate()
    except IOError as e:
        logger.warning("Failed to restore GRUB os-prober setting: %s", e)


# --- Main Execution ---
def run():
    """Main entry point for the module"""
    try:
        validate_global_storage()

        # Get configuration values
        config = libcalamares.job.configuration
        bootloader_var = config.get("bootLoaderVar", "bootloader")
        bootloader = libcalamares.globalstorage.value(bootloader_var)

        if not bootloader:
            logger.warning("No bootloader specified in global storage")
            return None

        if bootloader.lower() == "none":
            logger.info("Skipping bootloader configuration (user selected 'none')")
            return None

        # Get EFI directory
        efi_dir = libcalamares.globalstorage.value("efiSystemPartition", "/boot/efi")

        # Dispatch to handler
        if bootloader == "systemd-boot":
            handle_systemd_boot(efi_dir)
        elif bootloader == "grub":
            handle_grub()
        else:
            logger.warning("Unsupported bootloader: %s", bootloader)

    except MissingGlobalStorageError as e:
        logger.error("Configuration error: %s", e)
        return _("Missing system configuration - cannot configure boot entries.")
    except BootloaderConfigError as e:
        logger.error("Boot configuration failed: %s", e)
        return _("Failed to configure boot entries for Windows.")
    except Exception as e:
        logger.exception("Unexpected error during Windows boot configuration")
        return _("Critical error during boot configuration: {}").format(str(e))

    return None
