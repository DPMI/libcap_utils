#ifndef CAPUTILS_LOG_H
#define CAPUTILS_LOG_H

#include "caputils/capture.h"
#include "caputils/stream.h"

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

	/* layer limitations */
	FORMAT_LAYER_BIT         = 29,
	FORMAT_LAYER_APPLICATION = (4<<FORMAT_LAYER_BIT),
	FORMAT_LAYER_TRANSPORT   = (3<<FORMAT_LAYER_BIT),
	FORMAT_LAYER_LINK        = (2<<FORMAT_LAYER_BIT),
	FORMAT_LAYER_DPMI        = (1<<FORMAT_LAYER_BIT),
};

/**
 * Write a description of the packet in cp to fp.
 * @param flags Bitmask of FORMAT_FLAGS.
 */
void format_pkg(FILE* fp, const stream_t st, const struct cap_header* cp, unsigned int flags);

#ifdef __cplusplus
}
#endif

#endif /* CAPUTILS_LOG_H */
