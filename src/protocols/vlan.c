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
#include "caputils/caputils.h"

enum caputils_protocol_type ethertype_next(const unsigned int ethertype);

static enum caputils_protocol_type vlan_next(struct header_chunk* header, const char* ptr, const char** out){
	const unsigned int h_proto  = ntohs(((const uint16_t*)ptr)[1]);

	*out = ptr + sizeof(uint32_t);
	return ethertype_next(h_proto);
}

static void vlan_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	const unsigned int tci = ntohs(((const uint16_t*)ptr)[0]);

	fprintf(fp, ": 802.1Q vlan# %d", 0x0FFF & tci);
}

static void vlan_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	const unsigned int tci = ntohs(((const uint16_t*)ptr)[0]);
	const unsigned int pcp = (0xE000 & tci) >> 13;
	const unsigned int dei = (0x1000 & tci) >> 12;
	const unsigned int vid = (0x0FFF & tci);

	fprintf(fp, "%sTCI:                0x%02x\n", prefix, tci);
	fprintf(fp, "%sPCP:                %d\n", prefix, pcp);
	fprintf(fp, "%sDEI/CFI:            %d\n", prefix, dei);
	fprintf(fp, "%sVID:                %d\n", prefix, vid);
}

struct caputils_protocol protocol_vlan = {
	.name = "vlan",
	.size = sizeof(uint32_t),
	.next_payload = vlan_next,
	.format = vlan_format,
	.dump = vlan_dump,
};
