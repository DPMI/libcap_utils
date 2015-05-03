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

#include <caputils/log.h>
#include <caputils/send.h>
#include <caputils/packet.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

enum {
	PORT_DNS = 53,
	PORT_HTTP = 80,
};

#ifdef __cplusplus
extern "C" {
#endif

struct name_table {
	int value;
	const char* name;
};

/**
 * From a name table find entry with value and return name.
 * If value isn't found it returns def.
 */
const char* name_lookup(const struct name_table* table, int value, const char* def);

/**
 * Like fputs but only prints printable characters. Nonprintable characters is
 * replaced with \x## where ## is hex ASCII.
 * @note It also skips newlines.
 */
void fputs_printable(const char* str, FILE* fp);

/**
 * Test if there is enough data left for parsing.
 * @param cp capture header
 * @param ptr current read position
 * @param bytes number of bytes required.
 * @return non-zero if there isn't enough data left
 */
int limited_caplen(const struct cap_header* cp, const void* ptr, size_t bytes) __attribute__((visibility("default")));

/* layer 3 */
void print_arp(FILE* dst, const struct cap_header* cp, const struct ether_arp* arp);
void print_mp(FILE* fp, const struct cap_header* cp, const struct sendhead* send);
void print_mp_diagnostic(FILE* fp, const struct cap_header* cp, const char* data);
void print_mpls(FILE* fp, const struct cap_header* cp, const char* data);

/* layer 4 */
void print_icmp(FILE* fp, const struct cap_header* cp, net_t net, const struct icmphdr* icmp, unsigned int flags);

/* application layer */
void print_http(FILE* fp, const struct cap_header* cp, const char* payload, size_t size, unsigned int flags);

#ifdef __cplusplus
}
#endif
