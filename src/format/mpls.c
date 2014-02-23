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

#include "format.h"

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

void print_mpls(FILE* fp, const struct cap_header* cp, const char* data){
	const size_t bytes = cp->caplen - (data - cp->payload);
	if ( bytes < sizeof(union mpls_header) ){
		fputs(" MPLS [Packet size limited during capture]", fp);
		return;
	}

	const union mpls_header mpls = {.val = ntohl(*(uint32_t*)data)};
	fprintf(fp, " MPLS(label: %d, Exp: %d, S: %d, TTL: %d):",
		mpls.label, mpls.experimental, mpls.bottom, mpls.ttl
	);

	if ( !mpls.bottom ){
		print_mpls(fp, cp, data + sizeof(union mpls_header));
	}
}
