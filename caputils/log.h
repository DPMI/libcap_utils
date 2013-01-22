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

#ifndef CAPUTILS_LOG_H
#define CAPUTILS_LOG_H

#include "caputils/capture.h"
#include "caputils/stream.h"

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility push(default)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdarg.h>

int vlogmsg(FILE* fp, const char* tag, const char* fmt, va_list ap);
int logmsg(FILE* fp, const char* tag, const char* fmt, ...) __attribute__ ((format (printf, 3, 4)));

/**
 * Kind of `fputs(hexdump_str(..), fp)`
 */
void hexdump(FILE* fp, const char* data, size_t size);

/**
 * Dump the content of data as hexadecimal (and its ascii repr.) into a string.
 * Memory should be freed with free.
 */
char* hexdump_str(const char* data, size_t size);

enum FORMAT_FLAGS {
	FORMAT_DATE_BIT       = (1<<0),
	FORMAT_LOCAL_BIT      = (1<<1),
	FORMAT_DATE_UNIX      = 0x00,    /* Format date as unix timestamp. */
	FORMAT_DATE_STR       = 0x01,    /* Format date as string */
	FORMAT_DATE_UTC       = 0x00,    /* Show date in UTC. */
	FORMAT_DATE_LOCALTIME = 0x02,    /* Show date in local time. (only in effect when printing date as string)*/

	FORMAT_REL_TIMESTAMP  = (1<<2),  /* Show timestamps relative to first packet */
	FORMAT_HEXDUMP        = (1<<3),  /* Print hexdump of entire packet */
	FORMAT_HEADER         = (1<<4),  /* Show additional header information (e.g IP header length) */

	/* layer limitations */
	FORMAT_LAYER_BIT         = 29,
	FORMAT_LAYER_APPLICATION = (4<<FORMAT_LAYER_BIT),
	FORMAT_LAYER_TRANSPORT   = (3<<FORMAT_LAYER_BIT),
	FORMAT_LAYER_LINK        = (2<<FORMAT_LAYER_BIT),
	FORMAT_LAYER_DPMI        = (1<<FORMAT_LAYER_BIT),

	/* layer bits must be last, don't out any extra fields here */
};


struct format {
	uint64_t pktcount;
	timepico ref;
	int first;
	unsigned int flags;
};

/**
 * Setup a formatter for printing packets.
 *
 * @param st Stream packets comes from.
 * @param flags Bitmask of FORMAT_FLAGS.
 */
void format_setup(struct format* state, unsigned int flags);

/**
 * Write a description of the packet in cp to fp.
 */
void format_pkg(FILE* fp, struct format* state, const struct cap_header* cp);

/**
 * When writing stateful descriptions it is sometimes useful to ignore a packet
 * but increment the packet counter and time reference.
 */
void format_ignore(FILE* fp, struct format* state, const struct cap_header* cp);

#ifdef __cplusplus
}
#endif

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility pop
#endif

#endif /* CAPUTILS_LOG_H */
