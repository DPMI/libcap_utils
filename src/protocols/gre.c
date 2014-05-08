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

void print_gre(FILE* fp, const struct cap_header* cp, net_t net, const char* data, unsigned int flags){
	const size_t bytes = cp->caplen - (data - cp->payload);
	if ( bytes < sizeof(union gre_header) ){
		fputs("GRE [Packet size limited during capture]", fp);
		return;
	}

	const char* payload = data + sizeof(union gre_header);
	const union gre_header gre = {.val = ntohl(*(const uint32_t*)data)};
	fprintf(fp, "GRE(0x%02x):", gre.val & 0x00ff);

	/* skip optional parts of GRE header */
	if ( gre.checksum || gre.routing ) payload += 4;
	if ( gre.key      ) payload += 4;
	if ( gre.sequence ) payload += 4;

	/* print contained header */
	//print_eth(fp, cp, NULL, gre.proto, payload, flags);
}
