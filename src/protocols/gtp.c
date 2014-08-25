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

enum gtp_version {
	GTPv1,
	GTPv2,
	GTPvP,
};

enum {
	MSG_TPDU = 255,
};

struct gtp_stub_header {
	uint8_t reserved    : 4;
	uint8_t pt          : 1;
	uint8_t version     : 3;
};

struct gtp_v1_header {
	uint8_t npdu_flag   : 1;
	uint8_t seq_flag    : 1;
	uint8_t ext_flag    : 1;
	uint8_t reserved    : 1;
	uint8_t pt          : 1;
	uint8_t version     : 3;
	uint8_t message;
	uint16_t total;
	uint32_t teid;

	/* optional fields (since array size is 0 it won't affect sizeof) */
	struct {
		uint16_t seqnum;
		uint8_t npdu;
		uint8_t ext_type;
	} optional[0];
} __attribute__((packed));

struct gtp_v2_header {
	uint8_t reserved    : 3;
	uint8_t teid_flag   : 1;
	uint8_t piggyback   : 1;
	uint8_t version     : 3;
	uint8_t message;
	uint16_t total;
} __attribute__((packed));

struct gtp_prime_header {
	uint8_t hdr_len     : 1;
	uint8_t reserved    : 3;
	uint8_t pt          : 1;
	uint8_t version     : 3;
	uint8_t message;
	uint16_t plen;
	uint16_t seqnum;
} __attribute__((packed));

union gtp_header {
	struct gtp_stub_header stub;
	struct gtp_v1_header v1;
	struct gtp_v2_header v2;
	struct gtp_prime_header vp;
};

static enum gtp_version gtp_version(const union gtp_header* ptr){
	const struct gtp_stub_header* gtp = &ptr->stub;

	if ( gtp->version == 1 ){
		if ( gtp->pt == 1 ){
			return GTPv1;
		} else {
			return GTPvP;
		}
	} else if ( gtp->version == 2 ){
		return GTPv2;
	} else {
		fprintf(stderr, "invalid GTP version 0x%02x\n", gtp->version);
		abort();
	}
}

static const char* gtp_version_str(const union gtp_header* gtp){
	switch ( gtp_version(gtp) ){
	case GTPv1: return "GTPv1";
	case GTPv2: return "GTPv2";
	case GTPvP: return "GTP'";
	}
	return "GTP";
}

static int gtp_message_type(const union gtp_header* gtp){
	switch ( gtp_version(gtp) ){
	case GTPv1: return gtp->v1.message;
	case GTPv2: return gtp->v2.message;
	case GTPvP: return gtp->vp.message;
	}
	return 0;
}

static const char* gtp_message_type_str(const union gtp_header* gtp){
	const int type = gtp_message_type(gtp);
	switch (type){
	case 0:           return "Reserved";
	case 1:           return "Echo Request";
	case 2:           return "Echo Response";
	case 3:           return "Version Not Supported";
	case 4:           return "Node Alive Request";
	case 5:           return "Node Alive Response";
	case 6:           return "Redirection Request";
	case 7:           return "Redirection Response";
	case 8 ... 15:    return "Unknown";
	case 16:          return "Create PDP Context Request";
	case 17:          return "Create PDP Context Response";
	case 18:          return "Update PDP Context Request";
	case 19:          return "Update PDP Context Response";
	case 20:          return "Delete PDP Context Request";
	case 21:          return "Delete PDP Context Response";
	case 22 ... 25:   return "Unknown";
	case 26:          return "Error Indication";
	case 27:          return "PDU Notification Request";
	case 28:          return "PDU Notification Response";
	case 29:          return "PDU Notification Reject Request";
	case 30:          return "PDU Notification Reject Response";
	case 31:          return "Supported Extension Headers Notification";
	case 32:          return "Send Routeing Information for GPRS Request";
	case 33:          return "Send Routeing Information for GPRS Response";
	case 34:          return "Failure Report Request";
	case 35:          return "Failure Report Response";
	case 36:          return "Note MS GPRS Present Request";
	case 37:          return "Note MS GPRS Present Response";
	case 38 ... 47:   return "Unknown";
	case 48:          return "Identification Request";
	case 49:          return "Identification Response";
	case 50:          return "SGSN Context Request";
	case 51:          return "SGSN Context Response";
	case 52:          return "SGSN Context Acknowledge";
	case 53:          return "Forward Relocation Request";
	case 54:          return "Forward Relocation Response";
	case 55:          return "Forward Relocation Complete";
	case 56:          return "Relocation Cancel Request";
	case 57:          return "Relocation Cancel Response";
	case 58:          return "Forward SRNS Context";
	case 59:          return "Forward Relocation Complete Acknowledge";
	case 60:          return "Forward SRNS Context Acknowledge";
	case 61 ... 239:  return "Unknown";
	case 240:         return "Data Record Transfer Request";
	case 241:         return "Data Record Transfer Response";
	case 242 ... 254: return "Unknown";
	case 255:         return "T-PDU";
	}
	return "Unknown";
}

static size_t gtp_header_size(const union gtp_header* gtp){
	switch ( gtp_version(gtp) ){
	case GTPv1:
		if ( gtp->v1.ext_flag ){
			fprintf(stderr, "GTPv1 extension headers isn't supported (yet)\n");
			abort();
		}

		/* if either flag is set all fields is sent (but must not be interpreted
		 * unless the specific flag is set) */
		if ( gtp->v1.seq_flag || gtp->v1.npdu_flag || gtp->v1.ext_flag ){
			return sizeof(struct gtp_v1_header) + sizeof(uint32_t);
		} else {
			return sizeof(struct gtp_v1_header);
		}

	case GTPv2:
		return sizeof(struct gtp_v2_header) +
			(gtp->v2.teid_flag ? sizeof(uint32_t) : 0);

	case GTPvP:
		return sizeof(struct gtp_prime_header);
	}

	return sizeof(struct gtp_stub_header);
}

static size_t gtp_header_size_adapter(const struct header_chunk* header, const char* ptr){
	const union gtp_header* gtp = (const union gtp_header*)ptr;
	return gtp_header_size(gtp);
}

static enum caputils_protocol_type gtp_next(struct header_chunk* header, const char* ptr, const char** out){
	const union gtp_header* gtp = (const union gtp_header*)ptr;
	const enum gtp_version version = gtp_version(gtp);
	const int message_type = gtp_message_type(gtp);
	const char* payload = ptr + gtp_header_size(gtp);
	*out = payload;

	if ( version == GTPv2 && gtp->v2.piggyback ){
		return PROTOCOL_GTP;
	}

	if ( message_type != MSG_TPDU ){
		return PROTOCOL_DATA;
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

static void gtp_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	const union gtp_header* gtp = (const union gtp_header*)ptr;
	fprintf(fp, ": %s[%zd]", gtp_version_str(gtp), gtp_header_size(gtp));
}

static void gtp_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	const union gtp_header* gtp = (const union gtp_header*)ptr;

	fprintf(fp, "%sversion:            0x%02x\n", prefix, gtp->stub.version);
	fprintf(fp, "%smessage type:       %s (0x%02x)\n", prefix, gtp_message_type_str(gtp), gtp_message_type(gtp));

	switch ( gtp_version(gtp) ){
	case GTPv1:
		fprintf(fp, "%spt:                 %d\n", prefix, gtp->v1.pt);
		fprintf(fp, "%sextensions:         %s\n", prefix, gtp->v1.ext_flag ? "yes (not shown)" : "no");
		if ( gtp->v1.seq_flag ){
			fprintf(fp, "%ssequence num.:      0x%04d\n", prefix, ntohs(gtp->v1.optional[0].seqnum));
		} else {
			fprintf(fp, "%ssequence num.:      no\n", prefix);
		}
		if ( gtp->v1.npdu_flag ){
			fprintf(fp, "%snpdu:               0x%02d\n", prefix, gtp->v1.optional[0].npdu);
		} else {
			fprintf(fp, "%snpdu:               no\n", prefix);
		}
		fprintf(fp, "%slength:             %d octets\n", prefix, ntohs(gtp->v1.total));
		fprintf(fp, "%steid:               0x%08x\n", prefix, ntohl(gtp->v1.teid));
		break;

	case GTPv2:
		break;

	case GTPvP:
		break;
	}
}

struct caputils_protocol protocol_gtp = {
	.name = "GPRS Tunneling Protocol",
	.size = sizeof(struct gtp_stub_header),
	.size_dyn = gtp_header_size_adapter,
	.next_payload = gtp_next,
	.format = gtp_format,
	.dump = gtp_dump,
};
