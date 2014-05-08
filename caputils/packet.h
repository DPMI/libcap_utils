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

#ifndef CAPUTILS_PACKET_H
#define CAPUTILS_PACKET_H

#include <caputils/capture.h>
#include <caputils/protocol.h>

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility push(default)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

enum Level {
	LEVEL_INVALID = 0,
	LEVEL_PHYSICAL,
	LEVEL_LINK,
	LEVEL_NETWORK,
	LEVEL_TRANSPORT,
	LEVEL_APPLICATION,     /* not supported yet */
};

enum Level level_from_string(const char* str);

/**
 * Get payload sizes at the various levels (same as layer_size but excludes header).
 */
size_t payload_size(enum Level level, const cap_head* caphead);

/**
 * Get layer sizes at the various levels (same as payload_size but includes header).
 */
size_t layer_size(enum Level level, const cap_head* caphead);

/**
 * Get IPv4 header from packet.
 *
 * @param ether Ethernet header
 * @param payload If non-null returns a pointer to the IPv4 payload (not including optional header). Payload is undefined if packet is not IPv4.
 * @return Pointer to IPv4 header or NULL if packet does not contain IPv4.
 */
const struct ip* find_ipv4_header(const struct ethhdr* ether, const char** payload);
struct ip* find_ipv4_headerRW(struct ethhdr* ether, char** payload);

const struct tcphdr* find_tcp_header(const void* pkt, const struct ethhdr* ether, const struct ip* ip, uint16_t* src, uint16_t* dest);
const struct udphdr* find_udp_header(const void* pkt, const struct ethhdr* ether, const struct ip* ip, uint16_t* src, uint16_t* dest);

struct network {
	char net_src[120];   /* human-readable representation of src address */
	char net_dst[120];   /* human-readable representation of dst address */
	size_t plen;         /* payload size (not including network headers) */
};
typedef const struct network* net_t;

struct header_chunk {
	/* state */
	const struct cap_header* cp;                 /* packet being processed */
	const struct caputils_protocol* protocol;    /* protocol of current header */
	struct network last_net;                     /* filled each time network layer header is found */

	/* current header */
	union {
		const char* ptr;                           /* generic access to header (manual cast or arithmetic) */
		const struct ethhdr* ethhdr;               /* read as ethernet */
		const struct ip* ip;                       /* read as IPv4 */
	};
};

void header_init(struct header_chunk* header, const struct cap_header* cp);
int header_walk(struct header_chunk* header);
void header_dump(FILE* fp, const struct header_chunk* header, const char* prefix);
void header_format(FILE* fp, const struct header_chunk* header, int flags);

#ifdef __cplusplus
}
#endif

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility pop
#endif

#endif /* CAPUTILS_PACKET_H */
