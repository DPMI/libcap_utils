/**
 * libcap_utils - DPMI capture utilities
 * Copyright (C) 2003-2013 (see AUTHORS)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef CAPUTILS_PICOTIME_H
#define CAPUTILS_PICOTIME_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>

#define PICODIVIDER 1e12

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility push(default)
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Time struct for precision down to picoseconds
struct picotime {
	uint32_t tv_sec;
	uint64_t tv_psec;
} __attribute__((packed));

typedef struct picotime timepico;

//converts struct timeval to struct timepico (ms->ps)
timepico timeval_to_timepico(struct timeval);

//converts struct timespec to struct timepico (us->ps)
timepico timespec_to_timepico(struct timespec);

/**
 * Create a timepico from two integers.
 * Good for C++ or when lacking c99.
 */
timepico timepico_new(long int sec, long int psec);

/**
 * Get current timestamp expressed as picotime.
 * The precision is limited to nanoseconds.
 */
timepico timepico_now();

/**
 * Set timepico from string.
 * Return 0 on success.
 */
int timepico_from_string(timepico* dst, const char* str);

/**
 * Convert timepico to string (using strftime), psec ignored
 * @return dst or NULL if it fails.
 */
const char* timepico_to_string_r(const timepico* src, char* dst, size_t bytes, const char* fmt) __attribute__((format(strftime,4,0)));

/**
 * Like timepico_to_string but using static memory.
 */
const char* timepico_to_string(const timepico* src, const char* fmt) __attribute__((format(strftime,2,0)));

/**
 * Convert to a double.
 * Added in v0.7.14.
 */
double timepico_to_double(timepico tp);

//compares two struct timepico (ts1<ts2=-1, ts1>ts2=1, ts1==ts2=0)
int timecmp(const timepico *ts1, const timepico *ts2);

/**
 * Calculate a - b.
 */
timepico timepico_sub(timepico a, timepico b);

/**
 * Calculate a + b.
 */
timepico timepico_add(timepico a, timepico b);

#ifdef __cplusplus
}
#endif

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility pop
#endif

#endif /* CAPUTILS_PICOTIME_H */
