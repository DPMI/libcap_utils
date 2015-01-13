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

struct uint48 {
  unsigned long long v:48;
} __attribute__((packed));
typedef struct uint48 uint48_t;

/*  PTPv2 Common Header Format */
typedef struct ptpv2hdr {
  uint8_t tSpec;
  uint8_t verPtp;
  uint16_t len;
  uint8_t domainNumber;
  uint8_t reserved;
  uint16_t Flags;
  uint48_t correction;
  /*
     uint32_t correction_ns1;
     uint16_t correction_ns2;
  */
  uint16_t correction_sns;
  uint64_t clockIdentity;
  uint16_t sourcePort;
  uint16_t sequenceId;
  uint8_t control;
  uint8_t logMessage;
} __attribute__((packed)) ptpv2_ptpv2hdr_t;

typedef struct ptpv2_opt_originTimestamp {
  uint48_t ts_seconds;
  /*
  uint32_t ts_seconds1;
  uint16_t ts_seconds2;
  */
  uint32_t ts_nseconds;
} __attribute__((packed)) sctp_opt_originTs;

static void ptpv2_options(const struct cap_header* cp,const struct ptpv2hdr* ptpv2, int chunksize, FILE* dst){


	fprintf(dst,": (in development) ");
	//	const uint8_t* ptr = (const u_int8_t*)((const char*)ptpv2) + sizeof(struct ptpv2hdr);
	/* Treat message */
	fprintf(dst," %0x ", ptpv2->tSpec);

}

static enum caputils_protocol_type ptpv2_next(struct header_chunk* header, const char* ptr, const char** out){
  /*
	const struct ptpv2hdr* ptpv2 = (const struct ptpv2hdr*)ptr;
	const size_t header_size = 34; // http://en.wikipedia.org/wiki/PTPV2_packet_structure
	const size_t payload_size = header->last_net.plen - header_size;
	*out = ptr + header_size;
*/
	return PROTOCOL_DONE; /* Do not look for data after PTPV2 message, chunks... handled differently */
}


static void ptpv2_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	fputs(": PTPv", fp);

	if ( limited_caplen(header->cp, ptr, sizeof(struct ptpv2hdr)) ){
		fputs(" [Packet size limited during capture]", fp);
		return;
	}

	const struct ptpv2hdr* ptpv2 = (const struct ptpv2hdr*)ptr;
	const size_t header_size = 34;
	const size_t payload_size = header->last_net.plen - header_size;
	if ( flags & FORMAT_HEADER ){
		fprintf(fp, "(HDR[%zd]DATA[%zd])", header_size, payload_size);
	}

	const uint8_t verPtp = ptpv2->verPtp;
	fprintf(fp, "%u  ", verPtp);
	ptpv2_options(header->cp, ptpv2, payload_size, fp);
}

static void ptpv2_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	if ( limited_caplen(header->cp, ptr, sizeof(struct ptpv2hdr)) ){
		fprintf(fp, "%s[Packet size limited during capture]", prefix);
		return;
	}

	const struct ptpv2hdr* ptpv2 = (const struct ptpv2hdr*)ptr;
	fprintf(fp, "%stSpec:              %d\n", prefix, ptpv2->tSpec);
	fprintf(fp, "%sversion:            %d\n", prefix, ptpv2->verPtp);
	fprintf(fp, "%slength:             %u\n", prefix, ntohs(ptpv2->len));
	fprintf(fp, "%sdomain:             %u\n", prefix, ntohs(ptpv2->domainNumber));
}

struct caputils_protocol protocol_ptpv2 = {
	.name = "PTPV2",
	.size = sizeof(struct ptpv2hdr),
	.next_payload = ptpv2_next,
	.format = ptpv2_format,
	.dump = ptpv2_dump,
};
