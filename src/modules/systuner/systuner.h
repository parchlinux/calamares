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

#ifndef SYSTUNER_H
#define SYSTUNER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SYSTUNER_VERSION "0.1.0"
#define SYSTUNER_MAX_PARAMS 32
#define SYSTUNER_DEFAULT_CONF_PATH "/etc/sysctl.d/99-systuner.conf"

/**
 * Tuning profile modes
 */
typedef enum {
    SYSTUNER_PROFILE_DESKTOP = 0,   /* Balanced responsiveness for interactive desktop */
    SYSTUNER_PROFILE_GAMING,        /* Ultra-low stutter, optimized map count, eager writeback */
    SYSTUNER_PROFILE_SERVER,        /* Throughput-oriented, larger writeback windows */
    SYSTUNER_PROFILE_LAPTOP,        /* Battery-aware flush timers, balanced cache */
    SYSTUNER_PROFILE_LOW_MEM,       /* Low memory footprint, aggressive cache control */
    SYSTUNER_PROFILE_COUNT
} systuner_profile_t;

/**
 * Primary storage drive classification
 */
typedef enum {
    SYSTUNER_STORAGE_ALL_NONROT = 0, /* Fast NVMe / SATA SSD */
    SYSTUNER_STORAGE_HYBRID,         /* Mix of SSD and HDD */
    SYSTUNER_STORAGE_ROTATIONAL,     /* Rotational HDD */
    SYSTUNER_STORAGE_UNKNOWN
} systuner_storage_t;

/**
 * Discovered system specifications
 */
typedef struct {
    uint64_t total_ram_bytes;        /* Total physical RAM in bytes */
    uint64_t total_swap_bytes;       /* Total swap space in bytes */
    uint64_t available_ram_bytes;    /* Currently available RAM in bytes */
    bool has_zram;                   /* True if zram device is mounted as swap */
    bool is_battery_powered;         /* True if battery power supply detected */
    uint32_t cpu_cores;              /* Number of active CPU cores */
    systuner_storage_t storage_type; /* Detected primary storage category */
    char hostname[256];              /* System hostname */
    char kernel_release[256];        /* Linux kernel release */
} systuner_sysinfo_t;

/**
 * Single sysctl parameter configuration
 */
typedef struct {
    char key[64];                    /* e.g. "vm.dirty_background_bytes" */
    uint64_t recommended_val;        /* Computed optimal value */
    uint64_t current_val;            /* Existing value in running kernel */
    bool has_current_val;            /* True if current value could be queried */
    char description[128];           /* Human-readable explanation */
} systuner_param_t;

/**
 * Complete tuning configuration plan
 */
typedef struct {
    systuner_profile_t profile;
    systuner_sysinfo_t sysinfo;
    systuner_param_t params[SYSTUNER_MAX_PARAMS];
    size_t param_count;
} systuner_config_t;

/* --- Core API Functions --- */

/**
 * Convert profile enum to string identifier
 */
const char *systuner_profile_to_string(systuner_profile_t profile);

/**
 * Parse string into profile enum
 * Returns true on success, false on unknown profile name
 */
bool systuner_parse_profile(const char *name, systuner_profile_t *out_profile);

/**
 * Convert storage type enum to string
 */
const char *systuner_storage_to_string(systuner_storage_t storage);

/**
 * Probe hardware and kernel metrics from /proc and /sys
 * Returns 0 on success, negative error code on failure.
 */
int systuner_collect_sysinfo(systuner_sysinfo_t *info);

/**
 * Calculate recommended kernel parameters based on collected sysinfo and profile.
 * Returns 0 on success, negative error code on failure.
 */
int systuner_generate_config(const systuner_sysinfo_t *info,
                             systuner_profile_t profile,
                             systuner_config_t *config);

/**
 * Read current live sysctl values for each parameter in the config from /proc/sys.
 * Returns 0 on success, negative error code on failure.
 */
int systuner_populate_current_values(systuner_config_t *config);

/**
 * Render configuration in sysctl.d syntax (KEY = VALUE) into buffer.
 * Returns bytes written on success, negative error code on failure.
 */
int systuner_render_sysctl(const systuner_config_t *config, char *buffer, size_t bufsize);

/**
 * Render configuration and sysinfo in JSON format into buffer.
 * Returns bytes written on success, negative error code on failure.
 */
int systuner_render_json(const systuner_config_t *config, char *buffer, size_t bufsize);

/**
 * Render human-readable comparison table into buffer.
 * Returns bytes written on success, negative error code on failure.
 */
int systuner_render_table(const systuner_config_t *config, char *buffer, size_t bufsize);

/**
 * Apply generated sysctl parameters live into /proc/sys (requires root).
 * Returns number of successfully applied parameters, or negative error code.
 */
int systuner_apply_live(const systuner_config_t *config);

/**
 * Write generated sysctl configuration to a file (e.g. /etc/sysctl.d/99-systuner.conf).
 * Returns 0 on success, negative error code on failure.
 */
int systuner_write_file(const systuner_config_t *config, const char *filepath);

#ifdef __cplusplus
}
#endif

#endif /* SYSTUNER_H */
