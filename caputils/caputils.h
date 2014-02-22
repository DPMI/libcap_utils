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

#ifndef CAPUTILS_CAPUTILS_H
#define CAPUTILS_CAPUTILS_H

#include <stdint.h>
#include <stdio.h>
#include <net/ethernet.h>

/* Protocol definitions */
enum protocol_t {
	PROTOCOL_LOCAL_FILE = 0,
	PROTOCOL_ETHERNET_MULTICAST,
	PROTOCOL_UDP_MULTICAST,
	PROTOCOL_TCP_UNICAST,
};

/* forward declare */
struct stream;
struct filter;

#include <caputils/file.h>
#include <caputils/picotime.h>
#include <caputils/filter.h>
#include <caputils/stream.h>
#include <caputils/capture.h>
#include <caputils/utils.h>
#include <caputils/version.h>

/* linux-2.4 net/ethernet.h does not have this macro */
#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif

/* libc might not provide this if it is missing ipv6 support */
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif /* ETHERTYPE_IPV6 */

/* our ethernet format */
#define ETHERTYPE_MP 0x0810
#define ETHERTYPE_MP_DIAGNOSTIC 0x0811

#ifndef ETHERTYPE_MPLS
#define ETHERTYPE_MPLS 0x8847
#endif /* ETHERTYPE_MPLS */

#ifndef IPPROTO_OSPF
#define IPPROTO_OSPF 89
#endif

#define STPBRIDGES 0x0026
#define CDPVTP 0x016E

#ifndef IPPROTO_OSPF
#define IPPROTO_OSPF 89
#endif

struct llc_pdu_sn {
	uint8_t dsap;
	uint8_t ssap;
	uint8_t ctrl_1;
	uint8_t ctrl_2;
};

#endif /* CAPUTILS_CAPUTILS_H */
