/**
 * libcap_utils - DPMI capture utilities
 * Copyright (C) 2003-2015 (see AUTHORS)
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

struct ospf {
	uint8_t version;
	uint8_t type;
	uint16_t len;
	uint32_t router_id;
	uint32_t area_id;
	uint16_t checksum;
	uint16_t au_type;
	uint64_t auth;
};

enum {
	OSPF_TYPE_MIN = 0,

	OSPF_HELLO = 1,
	OSPF_DD = 2,
	OSPF_LSR = 3,
	OSPF_LSU = 4,
	OSPF_LSA = 5,

	OSPF_TYPE_MAX,
};

static const char* ospf_type_table[OSPF_TYPE_MAX] = {
	NULL,
	"Hello",
	"Database Description",
	"Link State Request",
	"Link State Update",
	"Link State Acknowledgement",
};

static const char* ospf_type_name(int type){
	if ( type > OSPF_TYPE_MIN || type < OSPF_TYPE_MAX ){
		return ospf_type_table[type];
	} else {
		return "Unknown";
	}
}

static enum caputils_protocol_type ospf_next(struct header_chunk* header, const char* ptr, const char** out){
	return PROTOCOL_DONE;
}

static void ospf_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	fputs(": OSPF", fp);

	if ( limited_caplen(header->cp, ptr, offsetof(struct ospf, type)) ){
		fputs(" [Packet size limited during capture]", fp);
		return;
	}

	const struct ospf* ospf = (const struct ospf*)ptr;

	fprintf(fp, " v%d %s %s --> %s", ospf->version, ospf_type_name(ospf->type),
		        header->last_net.net_src, header->last_net.net_dst);
}

static void ospf_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	if ( limited_caplen(header->cp, ptr, sizeof(struct tcphdr)) ){
		fprintf(fp, "%s[Packet size limited during capture]", prefix);
		return;
	}

	const struct ospf* ospf = (const struct ospf*)ptr;

	fprintf(fp, "%sversion:             %d\n", prefix, ospf->version);
	fprintf(fp, "%stype:                %s (%d)\n", prefix, ospf_type_name(ospf->type), ospf->type);
	fprintf(fp, "%slen:                 %d bytes\n", prefix, ntohs(ospf->len));
	fprintf(fp, "%srouter id:           0x%04x\n", prefix, ntohl(ospf->router_id));
	fprintf(fp, "%sarea id:             0x%04x\n", prefix, ntohl(ospf->area_id));
	fprintf(fp, "%schecksum:            0x%02x\n", prefix, ntohs(ospf->checksum));
	fprintf(fp, "%sautype:              %d\n", prefix, ntohs(ospf->au_type));
}

struct caputils_protocol protocol_ospf = {
	.name = "OSPF",
	.size = 0,
	.next_payload = ospf_next,
	.format = ospf_format,
	.dump = ospf_dump,
};
