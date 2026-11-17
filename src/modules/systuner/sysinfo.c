/*
 * Systuner - Linux System Responsiveness & Memory Tuner
 *
 * Copyright (C) 2026 Parch GNU/Linux
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "systuner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/utsname.h>

const char *systuner_storage_to_string(systuner_storage_t storage)
{
    switch (storage) {
    case SYSTUNER_STORAGE_ALL_NONROT:
        return "Non-rotational (NVMe/SSD)";
    case SYSTUNER_STORAGE_HYBRID:
        return "Hybrid (SSD + HDD)";
    case SYSTUNER_STORAGE_ROTATIONAL:
        return "Rotational (HDD)";
    case SYSTUNER_STORAGE_UNKNOWN:
    default:
        return "Unknown";
    }
}

static int parse_meminfo(systuner_sysinfo_t *info)
{
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) {
        return -errno;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        unsigned long long val_kb = 0;
        if (sscanf(line, "MemTotal: %llu kB", &val_kb) == 1) {
            info->total_ram_bytes = (uint64_t)val_kb * 1024ULL;
        } else if (sscanf(line, "MemAvailable: %llu kB", &val_kb) == 1) {
            info->available_ram_bytes = (uint64_t)val_kb * 1024ULL;
        } else if (sscanf(line, "SwapTotal: %llu kB", &val_kb) == 1) {
            info->total_swap_bytes = (uint64_t)val_kb * 1024ULL;
        }
    }

    fclose(fp);
    return 0;
}

static int check_zram_swap(systuner_sysinfo_t *info)
{
    info->has_zram = false;
    FILE *fp = fopen("/proc/swaps", "r");
    if (!fp) {
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "zram")) {
            info->has_zram = true;
            break;
        }
    }

    fclose(fp);
    return 0;
}

static int probe_storage(systuner_sysinfo_t *info)
{
    DIR *dir = opendir("/sys/block");
    if (!dir) {
        info->storage_type = SYSTUNER_STORAGE_UNKNOWN;
        return 0;
    }

    struct dirent *entry;
    size_t nonrot_count = 0;
    size_t rot_count = 0;

    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. and pseudo-devices (loop, ram, zram) */
        if (entry->d_name[0] == '.' ||
            strncmp(entry->d_name, "loop", 4) == 0 ||
            strncmp(entry->d_name, "ram", 3) == 0 ||
            strncmp(entry->d_name, "zram", 4) == 0 ||
            strncmp(entry->d_name, "dm-", 3) == 0) {
            continue;
        }

        char path[512];
        snprintf(path, sizeof(path), "/sys/block/%.255s/queue/rotational", entry->d_name);

        FILE *fp = fopen(path, "r");
        if (fp) {
            int is_rot = 0;
            if (fscanf(fp, "%d", &is_rot) == 1) {
                if (is_rot == 0) {
                    nonrot_count++;
                } else if (is_rot == 1) {
                    rot_count++;
                }
            }
            fclose(fp);
        }
    }

    closedir(dir);

    if (nonrot_count > 0 && rot_count > 0) {
        info->storage_type = SYSTUNER_STORAGE_HYBRID;
    } else if (nonrot_count > 0 && rot_count == 0) {
        info->storage_type = SYSTUNER_STORAGE_ALL_NONROT;
    } else if (rot_count > 0) {
        info->storage_type = SYSTUNER_STORAGE_ROTATIONAL;
    } else {
        info->storage_type = SYSTUNER_STORAGE_UNKNOWN;
    }

    return 0;
}

static int probe_power_supply(systuner_sysinfo_t *info)
{
    info->is_battery_powered = false;
    DIR *dir = opendir("/sys/class/power_supply");
    if (!dir) {
        return 0;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }

        char type_path[512];
        snprintf(type_path, sizeof(type_path), "/sys/class/power_supply/%.255s/type", entry->d_name);

        FILE *fp = fopen(type_path, "r");
        if (fp) {
            char ptype[64];
            if (fgets(ptype, sizeof(ptype), fp)) {
                if (strncmp(ptype, "Battery", 7) == 0) {
                    info->is_battery_powered = true;
                    fclose(fp);
                    break;
                }
            }
            fclose(fp);
        }
    }

    closedir(dir);
    return 0;
}

int systuner_collect_sysinfo(systuner_sysinfo_t *info)
{
    if (!info) {
        return -EINVAL;
    }

    memset(info, 0, sizeof(*info));

    /* Collect RAM and Swap */
    int rc = parse_meminfo(info);
    if (rc != 0) {
        return rc;
    }

    /* Check zram */
    check_zram_swap(info);

    /* Storage probing */
    probe_storage(info);

    /* Battery / Laptop check */
    probe_power_supply(info);

    /* CPU count */
    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    info->cpu_cores = (nprocs > 0) ? (uint32_t)nprocs : 1;

    /* Uname info */
    struct utsname un;
    if (uname(&un) == 0) {
        strncpy(info->hostname, un.nodename, sizeof(info->hostname) - 1);
        strncpy(info->kernel_release, un.release, sizeof(info->kernel_release) - 1);
    } else {
        strncpy(info->hostname, "unknown", sizeof(info->hostname) - 1);
        strncpy(info->kernel_release, "unknown", sizeof(info->kernel_release) - 1);
    }

    return 0;
}
