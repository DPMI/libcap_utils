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


union gtp_header {
	struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
// 		uint8_t nextheader   : 8;
// 		uint8_t pdunr        : 8;
// 		uint16_t sequencenr   : 16;
// 		uint32_t teid	      : 32;
// 		uint16_t total	      : 16;
// 		uint8_t message      : 8;
		uint8_t npdu	     : 1;
		uint8_t seqflag      : 1;
		uint8_t extension    : 1;
		uint8_t reserved     : 1;
		uint8_t type         : 1;
		uint8_t version      : 3;
#else /* __BYTE_ORDER */
		uint8_t version      : 3;
		uint8_t type         : 1;
		uint8_t reserved     : 1;
		uint8_t extension    : 1;
		uint8_t seqflag      : 1;
		uint8_t npdu	     : 1;
// 		uint8_t message      : 8;
// 		uint16_t total	      : 16;
// 		uint32_t teid	      : 32;
// 		uint16_t sequencenr   : 16;
// 		uint8_t pdunr        : 8;
// 		uint8_t nextheader   : 8;
		
#endif /* __BYTE_ORDER */

		uint8_t nextheader   : 8;
		uint8_t pdunr        : 8; 
		uint16_t sequencenr   : 16;
		uint32_t teid	      : 32;
		uint16_t total	      : 16;
		uint8_t message      : 8;	
		
	};
	uint32_t val;
} __attribute__((packed));


static enum caputils_protocol_type gtp_header_next_payload(struct header_chunk* header, const char* ptr, const char** out){
	const union gtp_header gtp = {.val = ntohl(*(const uint32_t*)ptr)};
	const char* payload = ptr + 8;//+ sizeof(union gtp_header);
	*out = payload;

	
	if ( (payload[0] & 0xf0) == 0x30 ){
		return PROTOCOL_IPV4;
	}

	/* detect IPv4 */
	if ( (payload[0] & 0xf0) == 0x40 ){
		return PROTOCOL_IPV4;
	}

// 	/* detect IPv6 */
// 	if ( (payload[0] & 0xf0) == 0x60 ){
//  		return PROTOCOL_IPV6;
// 	}

	return PROTOCOL_DATA;
}

static void gtp_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	const union gtp_header gtp = {.val = ntohl(*(const uint32_t*)ptr)};
	fprintf(fp, ": GTP(verison: %d, message type: %02x. length: %d)",
		gtp.version, gtp.message, gtp.total);
}

static void gtp_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	const union gtp_header gtp = {.val = ntohl(*(const uint32_t*)ptr)};
	char test = *ptr; 
	char test1 = *(ptr+1); 
	char test2 = *(ptr+2);
	char test3 = *(ptr+3);
	const char* payload = ptr + sizeof(union gtp_header);
	fprintf(fp,"GTPoutput%0x %0x %0x %0x	\n", test, test1, test2, test3 );
	fprintf(fp, "%sversion:              %0x\n", prefix, gtp.version);
	fprintf(fp, "%message type:          %0X\n", prefix, gtp.message);
	fprintf(fp, "%slength:               %d\n", prefix, gtp.total);
	fprintf(fp, "%steid:                 0x%08x\n", prefix, gtp.teid);
}





struct caputils_protocol protocol_gtp = {
	.name = "GTP",
	//.size = sizeof(uint32_t),
	.next_payload = gtp_header_next_payload,
	.format = gtp_format,
	.dump = gtp_dump,
};

