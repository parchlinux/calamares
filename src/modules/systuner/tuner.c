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
#include <string.h>
#include <strings.h>
#include <errno.h>

const char *systuner_profile_to_string(systuner_profile_t profile)
{
    switch (profile) {
    case SYSTUNER_PROFILE_DESKTOP:
        return "desktop";
    case SYSTUNER_PROFILE_GAMING:
        return "gaming";
    case SYSTUNER_PROFILE_SERVER:
        return "server";
    case SYSTUNER_PROFILE_LAPTOP:
        return "laptop";
    case SYSTUNER_PROFILE_LOW_MEM:
        return "low-memory";
    default:
        return "unknown";
    }
}

bool systuner_parse_profile(const char *name, systuner_profile_t *out_profile)
{
    if (!name || !out_profile) {
        return false;
    }

    if (strcasecmp(name, "desktop") == 0) {
        *out_profile = SYSTUNER_PROFILE_DESKTOP;
        return true;
    }
    if (strcasecmp(name, "gaming") == 0 || strcasecmp(name, "game") == 0) {
        *out_profile = SYSTUNER_PROFILE_GAMING;
        return true;
    }
    if (strcasecmp(name, "server") == 0) {
        *out_profile = SYSTUNER_PROFILE_SERVER;
        return true;
    }
    if (strcasecmp(name, "laptop") == 0 || strcasecmp(name, "battery") == 0) {
        *out_profile = SYSTUNER_PROFILE_LAPTOP;
        return true;
    }
    if (strcasecmp(name, "low-memory") == 0 || strcasecmp(name, "lowmem") == 0 ||
        strcasecmp(name, "low-mem") == 0) {
        *out_profile = SYSTUNER_PROFILE_LOW_MEM;
        return true;
    }

    return false;
}

static void add_param(systuner_config_t *config,
                      const char *key,
                      uint64_t val,
                      const char *desc)
{
    if (config->param_count >= SYSTUNER_MAX_PARAMS) {
        return;
    }

    systuner_param_t *p = &config->params[config->param_count++];
    memset(p, 0, sizeof(*p));
    snprintf(p->key, sizeof(p->key), "%s", key);
    p->recommended_val = val;
    p->current_val = 0;
    p->has_current_val = false;
    snprintf(p->description, sizeof(p->description), "%s", desc);
}

int systuner_generate_config(const systuner_sysinfo_t *info,
                             systuner_profile_t profile,
                             systuner_config_t *config)
{
    if (!info || !config) {
        return -EINVAL;
    }

    memset(config, 0, sizeof(*config));
    config->profile = profile;
    config->sysinfo = *info;
    config->param_count = 0;

    uint64_t ram_mb = info->total_ram_bytes / (1024ULL * 1024ULL);

    /* 1. vm.dirty_background_bytes */
    uint64_t dirty_bg_bytes = 67108864ULL; /* 64 MB default */
    if (profile == SYSTUNER_PROFILE_LOW_MEM || ram_mb < 2048) {
        dirty_bg_bytes = 16777216ULL; /* 16 MB */
    } else if (profile == SYSTUNER_PROFILE_GAMING) {
        dirty_bg_bytes = (ram_mb < 16384) ? 33554432ULL : 67108864ULL; /* 32 - 64 MB */
    } else if (profile == SYSTUNER_PROFILE_SERVER) {
        dirty_bg_bytes = (ram_mb >= 65536) ? 268435456ULL : (ram_mb >= 16384 ? 134217728ULL : 67108864ULL);
    } else {
        /* Desktop / Laptop */
        if (ram_mb < 4096) {
            dirty_bg_bytes = 33554432ULL; /* 32 MB */
        } else if (ram_mb >= 65536) {
            dirty_bg_bytes = 134217728ULL; /* 128 MB */
        } else {
            dirty_bg_bytes = 67108864ULL; /* 64 MB */
        }
    }
    add_param(config, "vm.dirty_background_bytes", dirty_bg_bytes,
              "Start background writeout early to prevent I/O queues blocking GUI/audio");

    /* 2. vm.dirty_bytes */
    uint64_t dirty_bytes = dirty_bg_bytes * 4ULL;
    if (profile == SYSTUNER_PROFILE_LOW_MEM) {
        dirty_bytes = 67108864ULL; /* 64 MB */
    }
    add_param(config, "vm.dirty_bytes", dirty_bytes,
              "Hard cap on dirty pages to eliminate heavy disk write freezing");

    /* 3. vm.dirty_expire_centisecs */
    uint64_t expire_cs = 3000; /* 30 seconds default for desktop/server */
    if (profile == SYSTUNER_PROFILE_LAPTOP) {
        expire_cs = 6000; /* 60 seconds on battery allows drive spin down */
    } else if (profile == SYSTUNER_PROFILE_GAMING) {
        expire_cs = 1500; /* 15 seconds to avoid large write bursts */
    }
    add_param(config, "vm.dirty_expire_centisecs", expire_cs,
              "Max age of dirty pages before writeback is forced");

    /* 4. vm.dirty_writeback_centisecs */
    uint64_t wb_cs = 500; /* 5 seconds default for desktop/server */
    if (profile == SYSTUNER_PROFILE_LAPTOP) {
        wb_cs = 1500; /* 15 seconds to minimize CPU/disk wakeups */
    } else if (profile == SYSTUNER_PROFILE_GAMING) {
        wb_cs = 250; /* 2.5 seconds frequent micro-flushes */
    }
    add_param(config, "vm.dirty_writeback_centisecs", wb_cs,
              "Kernel flusher wake-up interval for unwritten data");

    /* 5. vm.swappiness */
    uint64_t swappiness = 10;
    if (info->has_zram) {
        /* ZRAM swap: compressed RAM is fast, swapping is desirable */
        swappiness = (profile == SYSTUNER_PROFILE_GAMING) ? 60 : 100;
    } else if (info->total_swap_bytes == 0) {
        swappiness = 10;
    } else if (info->storage_type == SYSTUNER_STORAGE_ROTATIONAL) {
        /* HDD swap: avoid disk thrashing */
        swappiness = 1;
    } else {
        /* Fast SSD swap */
        if (profile == SYSTUNER_PROFILE_GAMING) {
            swappiness = 5;
        } else if (profile == SYSTUNER_PROFILE_SERVER) {
            swappiness = 20;
        } else {
            swappiness = 10;
        }
    }
    add_param(config, "vm.swappiness", swappiness,
              "Kernel swapping aggression (tuned for zram vs disk swap)");

    /* 6. vm.vfs_cache_pressure */
    uint64_t vfs_cache_pressure = 50;
    if (profile == SYSTUNER_PROFILE_SERVER) {
        vfs_cache_pressure = 100;
    } else if (profile == SYSTUNER_PROFILE_LOW_MEM) {
        vfs_cache_pressure = 150;
    } else {
        vfs_cache_pressure = 50;
    }
    add_param(config, "vm.vfs_cache_pressure", vfs_cache_pressure,
              "Retain inode and directory caches to accelerate file browsing & CLI");

    /* 7. vm.page-cluster (swap clustering) */
    if (info->has_zram || info->storage_type == SYSTUNER_STORAGE_ALL_NONROT) {
        add_param(config, "vm.page-cluster", 0,
                  "Disable sequential swap clustering for zero-latency 4K random paging");
    }

    /* 8. vm.max_map_count (memory map areas for gaming/Proton/JVM/containers) */
    uint64_t max_map = 1048576ULL;
    if (profile == SYSTUNER_PROFILE_GAMING) {
        max_map = 2147483642ULL;
    } else if (profile == SYSTUNER_PROFILE_LOW_MEM) {
        max_map = 262144ULL;
    }
    add_param(config, "vm.max_map_count", max_map,
              "Enlarge maximum memory map areas to prevent Proton/Steam/JVM crash & stutter");

    return 0;
}
