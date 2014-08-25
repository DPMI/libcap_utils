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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "src/format/format.h"
#include <endian.h>

union mpls_header {
	struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		uint32_t ttl           : 8;
		uint32_t bottom        : 1;
		uint32_t experimental  : 3;
		uint32_t label         : 20;
#else /* __BYTE_ORDER */
		uint32_t label         : 20;
		uint32_t experimental  : 3;
		uint32_t bottom        : 1;
		uint32_t ttl           : 8;
#endif /* __BYTE_ORDER */
	};
	uint32_t val;
} __attribute__((packed));

union pw_control {
	struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		uint32_t sequence      : 16;
		uint32_t reserved      : 12;
		uint32_t zero          : 4;
#else /* __BYTE_ORDER */
		uint32_t zero          : 4;
		uint32_t reserved      : 12;
		uint32_t sequence      : 16;
#endif /* __BYTE_ORDER */
	};
	uint32_t val;
} __attribute__((packed));

static enum caputils_protocol_type mpls_next_payload(struct header_chunk* header, const char* ptr, const char** out){
	const union mpls_header mpls = {.val = ntohl(*(const uint32_t*)ptr)};
	const char* payload = ptr + sizeof(union mpls_header);
	*out = payload;

	/* traverse all MPLS headers */
	if ( !mpls.bottom ){
		return PROTOCOL_MPLS;
	}

	/** @todo need to check if the next byte is really readable */

	/* detect pseudo-wire control word */
	if ( (payload[0] & 0xf0) == 0 ){
		return PROTOCOL_PW;
	}

	/* detect IPv4 */
	if ( (payload[0] & 0xf0) == 0x40 ){
		return PROTOCOL_IPV4;
	}

	/* detect IPv6 */
	if ( (payload[0] & 0xf0) == 0x60 ){
		return PROTOCOL_IPV6;
	}

	return PROTOCOL_DATA;
}

static void mpls_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	const union mpls_header mpls = {.val = ntohl(*(const uint32_t*)ptr)};
	fprintf(fp, ": MPLS(label: %d, Exp: %d, S: %d, TTL: %d)",
		mpls.label, mpls.experimental, mpls.bottom, mpls.ttl
	);
}

static void mpls_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	const union mpls_header mpls = {.val = ntohl(*(const uint32_t*)ptr)};
	fprintf(fp, "%slabel:              %d\n", prefix, mpls.label);
	fprintf(fp, "%sexperimental:       %d\n", prefix, mpls.experimental);
	fprintf(fp, "%sbottom:             %s\n", prefix, mpls.bottom ? "yes" : "no");
	fprintf(fp, "%sTTL:                %d\n", prefix, mpls.ttl);
}

static enum caputils_protocol_type pw_next_payload(struct header_chunk* header, const char* ptr, const char** out){
	*out += sizeof(union pw_control);
	return PROTOCOL_ETHERNET;
}

static void pw_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	const union pw_control pw = {.val = ntohl(*(const uint32_t*)ptr)};
	fprintf(fp, ": PW(seq: %d)", pw.sequence);
}

static void pw_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	const union pw_control pw = {.val = ntohl(*(const uint32_t*)ptr)};
	fprintf(fp, "%ssequence:           %d\n", prefix, pw.sequence);
}

struct caputils_protocol protocol_mpls = {
	.name = "MPLS",
	.size = sizeof(uint32_t),
	.next_payload = mpls_next_payload,
	.format = mpls_format,
	.dump = mpls_dump,
};

struct caputils_protocol protocol_pw = {
	.name = "PW",
	.size = sizeof(uint32_t),
	.next_payload = pw_next_payload,
	.format = pw_format,
	.dump = pw_dump,
};
