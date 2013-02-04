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

#ifdef __cplusplus
}
#endif

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility pop
#endif

#endif /* CAPUTILS_PACKET_H */
