#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# SPDX-FileCopyrightText: 2026 Parch Linux Developers
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Parch Migration Assistant Execution Job

import os
import shutil
import subprocess
import libcalamares

import gettext
_ = gettext.translation("calamares-python",
                        localedir=libcalamares.utils.gettext_path(),
                        languages=libcalamares.utils.gettext_languages(),
                        fallback=True).gettext

def pretty_name():
    return _("Migrating user data from previous system…")

def run():
    gs = libcalamares.globalstorage
    source_partition = gs.value("migrationSourcePartition")
    source_user = gs.value("migrationSourceUser")
    migration_items = gs.value("migrationItems")
    source_os = gs.value("migrationOs") or "Windows"
    username = gs.value("username")
    root_mount_point = gs.value("rootMountPoint")

    if not source_partition or not source_user or not migration_items or not username:
        libcalamares.utils.debug("Migration Assistant: No migration parameters provided. Skipping.")
        return None

    if not root_mount_point or not os.path.exists(root_mount_point):
        libcalamares.utils.warning("Migration Assistant: Invalid root mount point.")
        return None

    target_home = os.path.join(root_mount_point, "home", username)
    if not os.path.exists(target_home):
        libcalamares.utils.warning(f"Migration Assistant: Target home directory {target_home} does not exist.")
        return None

    temp_mount = "/tmp/parch-migration-run"
    os.makedirs(temp_mount, exist_ok=True)

    libcalamares.utils.debug(f"Migration Assistant: Mounting {source_partition} at {temp_mount}")

    # Attempt read-only mount
    try:
        mount_cmd = ["mount", "-o", "ro,noload", source_partition, temp_mount]
        r = subprocess.run(mount_cmd, capture_output=True, text=True)
        if r.returncode != 0:
            # Fallback for NTFS without noload
            r = subprocess.run(["mount", "-o", "ro", source_partition, temp_mount], capture_output=True, text=True)
            if r.returncode != 0:
                libcalamares.utils.warning(f"Migration Assistant: Failed to mount {source_partition}: {r.stderr}")
                return None
    except Exception as e:
        libcalamares.utils.warning(f"Migration Assistant: Mount exception: {e}")
        return None

    try:
        # Determine source user directory
        if source_os == "Windows":
            user_dir = os.path.join(temp_mount, "Users", source_user)
            if not os.path.exists(user_dir):
                # Try case-insensitive search
                users_path = os.path.join(temp_mount, "Users")
                if os.path.exists(users_path):
                    for u in os.listdir(users_path):
                        if u.lower() == source_user.lower():
                            user_dir = os.path.join(users_path, u)
                            break
        else:
            user_dir = os.path.join(temp_mount, "home", source_user)

        if not os.path.exists(user_dir):
            libcalamares.utils.warning(f"Migration Assistant: User dir {user_dir} not found on source partition.")
            return None

        folder_mapping = {
            "documents": ["Documents", "My Documents", "اسناد"],
            "downloads": ["Downloads", "دریافت‌ها"],
            "pictures": ["Pictures", "My Pictures", "تصاویر"],
            "music": ["Music", "My Music", "آهنگ‌ها"],
            "videos": ["Videos", "My Videos", "ویدیوها"],
            "desktop": ["Desktop", "میزکار"]
        }

        imported_paths = []

        for item in migration_items:
            item_lower = item.lower()
            if item_lower in folder_mapping:
                target_folder_name = item_lower.capitalize()
                dest_dir = os.path.join(target_home, target_folder_name)
                os.makedirs(dest_dir, exist_ok=True)

                # Look for matching source folder
                found_src = None
                for candidate in folder_mapping[item_lower]:
                    candidate_path = os.path.join(user_dir, candidate)
                    if os.path.exists(candidate_path) and os.path.isdir(candidate_path):
                        found_src = candidate_path
                        break

                if found_src:
                    libcalamares.utils.debug(f"Migration Assistant: Copying {found_src} -> {dest_dir}")
                    try:
                        shutil.copytree(found_src, dest_dir, dirs_exist_ok=True)
                        imported_paths.append(dest_dir)
                    except Exception as copy_err:
                        libcalamares.utils.warning(f"Migration error copying {found_src}: {copy_err}")

            elif item_lower == "bookmarks":
                # Search for browser bookmarks
                dest_bookmarks_dir = os.path.join(target_home, "Desktop")
                os.makedirs(dest_bookmarks_dir, exist_ok=True)
                
                # Check Chrome / Edge / Brave
                chrome_bookmarks = [
                    os.path.join(user_dir, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Bookmarks"),
                    os.path.join(user_dir, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Bookmarks"),
                    os.path.join(user_dir, ".config", "google-chrome", "Default", "Bookmarks"),
                    os.path.join(user_dir, ".config", "chromium", "Default", "Bookmarks"),
                ]
                for cb in chrome_bookmarks:
                    if os.path.exists(cb):
                        dest_file = os.path.join(dest_bookmarks_dir, "Imported_Chrome_Bookmarks.json")
                        try:
                            shutil.copy2(cb, dest_file)
                            imported_paths.append(dest_file)
                            libcalamares.utils.debug(f"Migration Assistant: Imported bookmarks from {cb}")
                        except Exception as b_err:
                            libcalamares.utils.warning(f"Failed to copy bookmarks: {b_err}")

        # Fix ownership to new user
        for p in imported_paths:
            try:
                subprocess.run(["chown", "-R", f"{username}:{username}", p], check=False)
            except Exception as chown_err:
                libcalamares.utils.warning(f"chown error on {p}: {chown_err}")

        # Also ensure entire home directory ownership is clean
        subprocess.run(["chown", "-R", f"{username}:{username}", target_home], check=False)

    finally:
        # Unmount temporary mount
        subprocess.run(["umount", "-l", temp_mount], check=False)

    libcalamares.utils.debug("Migration Assistant: Data migration finished successfully.")
    return None
