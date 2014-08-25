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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "src/format/format.h"

union gre_header {
	struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		uint32_t proto         : 16;
		uint32_t version       : 3;
		uint32_t reserved      : 5;
		uint32_t recursion     : 3;
		uint32_t strict        : 1;
		uint32_t sequence      : 1;
		uint32_t key           : 1;
		uint32_t routing       : 1;
		uint32_t checksum      : 1;
#else /* __BYTE_ORDER */
		uint32_t checksum      : 1;
		uint32_t routing       : 1;
		uint32_t key           : 1;
		uint32_t sequence      : 1;
		uint32_t strict        : 1;
		uint32_t recursion     : 3;
		uint32_t reserved      : 5;
		uint32_t version       : 3;
		uint32_t proto         : 16;
#endif /* __BYTE_ORDER */
	};
	uint32_t val;
} __attribute__((packed));

enum caputils_protocol_type ethertype_next(const unsigned int ethertype);

static enum caputils_protocol_type gre_next(struct header_chunk* header, const char* ptr, const char** out){
	const char* payload = ptr + sizeof(union gre_header);
	const union gre_header gre = {.val = ntohl(*(const uint32_t*)ptr)};

	/* skip optional parts of GRE header */
	if ( gre.checksum || gre.routing ) payload += 4;
	if ( gre.key      ) payload += 4;
	if ( gre.sequence ) payload += 4;

	*out = payload;
	return ethertype_next(gre.proto);
}

static void gre_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	const union gre_header gre = {.val = ntohl(*(const uint32_t*)ptr)};
	fprintf(fp, ": GRE(0x%02x)", gre.val & 0x00ff);
}

static void gre_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	const union gre_header gre = {.val = ntohl(*(const uint32_t*)ptr)};

	fprintf(fp, "%schecksum       		 %d\n", prefix, gre.checksum);
	fprintf(fp, "%srouting        		 %d\n", prefix, gre.routing);
	fprintf(fp, "%skey            		 %d\n", prefix, gre.key);
	fprintf(fp, "%ssequence       		 %d\n", prefix, gre.sequence);
	fprintf(fp, "%sstrict         		 %d\n", prefix, gre.strict);
	fprintf(fp, "%srecursion      		 %d\n", prefix, gre.recursion);
	fprintf(fp, "%sreserved       		 %d\n", prefix, gre.reserved);
	fprintf(fp, "%sversion        		 %d\n", prefix, gre.version);
	fprintf(fp, "%sproto          		 %d\n", prefix, gre.proto);
}

struct caputils_protocol protocol_gre = {
	.name = "GRE",
	.size = sizeof(union gre_header),
	.next_payload = gre_next,
	.format = gre_format,
	.dump = gre_dump,
};
