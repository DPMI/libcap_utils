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
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define PORT_DNS 53
#define PORT_HTTP 80

struct network {
	const char* net_src; /* human-readable representation of src address */
	const char* net_dst; /* human-readable representation of dst address */
	size_t plen;         /* payload size (not including network headers) */
};
typedef const struct network* net_t;

/**
 * Test if there is enough data left for parsing.
 * @param cp capture header
 * @param ptr current read position
 * @param bytes number of bytes required.
 * @return non-zero if there isn't enough data left
 */
int limited_caplen(const struct cap_header* cp, const void* ptr, size_t bytes);

/* layer 2 */
void print_eth(FILE* dst, const struct cap_header* cp, const struct ethhdr* eth, unsigned int flags);

/* layer 3 */
void print_ipproto(FILE* fp, const struct cap_header* cp, net_t net, uint8_t proto, const char* payload, unsigned int flags);
void print_ipv4(FILE* fp, const struct cap_header* cp, const struct ip* ip, unsigned int flags);
void print_ipv6(FILE* fp, const struct cap_header* cp, const struct ip6_hdr* ip, unsigned int flags);
void print_arp(FILE* dst, const struct cap_header* cp, const struct ether_arp* arp);
void print_mp(FILE* fp, const struct cap_header* cp, const struct sendhead* send);
void print_mp_diagnostic(FILE* fp, const struct cap_header* cp, const char* data);
void print_mpls(FILE* fp, const struct cap_header* cp, const char* data);
void print_gre(FILE* fp, const struct cap_header* cp, net_t net, const char* data, unsigned int flags);

/* layer 4 */
void print_tcp(FILE* fp, const struct cap_header* cp, net_t net, const struct tcphdr* tcp, unsigned int flags);
void print_udp(FILE* fp, const struct cap_header* cp, net_t net, const struct udphdr* udp, unsigned int flags);
void print_icmp(FILE* fp, const struct cap_header* cp, net_t net, const struct icmphdr* icmp, unsigned int flags);

/* application layer */
void print_dns(FILE* fp, const struct cap_header* cp, const char* payload, size_t size, unsigned int flags);
void print_http(FILE* fp, const struct cap_header* cp, const char* payload, size_t size, unsigned int flags);
