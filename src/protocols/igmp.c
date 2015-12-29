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

struct igmp {
	uint8_t type;
	uint8_t max_response_time;
	uint16_t checksum;
	uint32_t group_address;
};

enum {
	IGMP_GROUP_MEMBERSHIP_QUERY = 0x11,
	IGMP_V1_MEMBERSHIP_REPORT = 0x12,
	IGMP_DVMRP = 0x13,
	IGMP_PIMv1 = 0x14,
	IGMP_CISCO_TRACE = 0x15,
	IGMP_V2_MEMBERSHIP_REPORT = 0x16,
	IGMP_V2_LEAVE_GROUP = 0x17,
	IGMP_MULTICAST_TRACEROUTE_REPORT = 0x1e,
	IGMP_MULTICAST_TRACEROUTE = 0x1f,
	IGMP_V3_MEMBERSHIP_REPORT = 0x22,
	IGMP_MULTICAST_ROUTER_ADVERTISEMENT = 0x30,
	IGMP_MULTICAST_ROUTER_SOLICITATION = 0x31,
	IGMP_MULTICAST_ROUTER_TERMINATION = 0x32,
};

static const char* igmp_type_name(int type){
	switch ( type ){
	case IGMP_GROUP_MEMBERSHIP_QUERY: return "Group Membership Query";
	case IGMP_V1_MEMBERSHIP_REPORT: return "V1 Membership Report";
	case IGMP_DVMRP: return "DVMRP";
	case IGMP_PIMv1: return "PIMv1";
	case IGMP_CISCO_TRACE: return "Cisco Trace";
	case IGMP_V2_MEMBERSHIP_REPORT: return "V2 Membership Report";
	case IGMP_V2_LEAVE_GROUP: return "V2 Leave Group";
	case IGMP_MULTICAST_TRACEROUTE_REPORT: return "Multicast Traceroute Report";
	case IGMP_MULTICAST_TRACEROUTE: return "Multicast Traceroute";
	case IGMP_V3_MEMBERSHIP_REPORT: return "V3 Membership Report";
	case IGMP_MULTICAST_ROUTER_ADVERTISEMENT: return "Multicast Router Advertisement";
	case IGMP_MULTICAST_ROUTER_SOLICITATION: return "Multicast Router Solicitation";
	case IGMP_MULTICAST_ROUTER_TERMINATION: return "Multicast Router Termination";
	default: return "Unknown";
	}
}

static enum caputils_protocol_type igmp_next(struct header_chunk* header, const char* ptr, const char** out){
	return PROTOCOL_DONE;
}

static void igmp_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	fputs(": IGMP", fp);

	if ( limited_caplen(header->cp, ptr, offsetof(struct igmp, max_response_time)) ){
		fputs(" [Packet size limited during capture]", fp);
		return;
	}

	const struct igmp* igmp = (const struct igmp*)ptr;

	fprintf(fp, " %s %s", header->last_net.net_dst, igmp_type_name(igmp->type));
}

static void igmp_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	if ( limited_caplen(header->cp, ptr, sizeof(struct tcphdr)) ){
		fprintf(fp, "%s[Packet size limited during capture]", prefix);
		return;
	}

	const struct igmp* igmp = (const struct igmp*)ptr;

	fprintf(fp, "%stype:                %s (%d)\n", prefix, igmp_type_name(igmp->type), igmp->type);
	fprintf(fp, "%smax response time:   %d\n", prefix, igmp->max_response_time);
	fprintf(fp, "%sgroup address:       0x%04x\n", prefix, ntohl(igmp->group_address));
}

struct caputils_protocol protocol_igmp = {
	.name = "IGMP",
	.size = 0,
	.next_payload = igmp_next,
	.format = igmp_format,
	.dump = igmp_dump,
};
