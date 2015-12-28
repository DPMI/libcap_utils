/**
 * libcap_utils - DPMI capture utilities
 * Copyright (C) 2003-2014 (see AUTHORS)
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

#ifndef CAPUTILS_PROTOCOL_H
#define CAPUTILS_PROTOCOL_H

#include <caputils/capture.h>

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility push(default)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

enum caputils_protocol_type {
	PROTOCOL_UNKNOWN = 0,              /* unknown or invalid protocol */
	PROTOCOL_DONE,                     /* no more headers, shouldn't be any more payload */
	PROTOCOL_DATA,                     /* no more headers, payload is data */

	PROTOCOL_ARP = 3,
	PROTOCOL_CDP,
	PROTOCOL_DNS,
	PROTOCOL_ETHERNET,
	PROTOCOL_GRE,
	PROTOCOL_GTP,
	PROTOCOL_ICMP,
	PROTOCOL_IPV4,
	PROTOCOL_IPV6,
	PROTOCOL_MPLS,
	PROTOCOL_OSPF,
	PROTOCOL_PTPv2,
	PROTOCOL_PW,
	PROTOCOL_SCTP,
	PROTOCOL_STP,
	PROTOCOL_TCP,
	PROTOCOL_UDP,
	PROTOCOL_VLAN,

	PROTOCOL_NUM_AVAILABLE,
};

struct header_chunk;
typedef size_t (*size_callback)(const struct header_chunk* header, const char* ptr);
typedef enum caputils_protocol_type (*payload_callback)(struct header_chunk*, const char* ptr, const char** out);
typedef void (*format_callback)(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags);
typedef void (*dump_callback)(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags);

struct caputils_protocol {
	enum caputils_protocol_type type;  /* type id */
	const char* name;                  /* human-readable name of this protocol */
	size_t size;                       /* (min) number of bytes required to parse this header (if set to 0 it will always parse, giving you the opportunity to parse as much as possible) */
	size_callback size_dyn;            /* optional function to calculate the actual size of this header. If set it has precedence over static size */
	int partial_print;                 /* if non-zero the format- and dump-functions is supported even for truncated packets */
	payload_callback next_payload;     /* get pointer to next payload */
	format_callback format;            /* print representation of this header chunk */
	dump_callback dump;                /* dump all fields in this header chunk */
};

/**
 * Get a protocol descriptor from type name.
 */
struct caputils_protocol* protocol_get(enum caputils_protocol_type type);

#ifdef __cplusplus
}
#endif

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility pop
#endif

#endif /* CAPUTILS_PACKET_H */
