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

#ifndef CAPUTILS_INTERFACE_H
#define CAPUTILS_INTERFACE_H

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility push(default)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <net/if.h>
#include <net/ethernet.h>

struct iface {
	char if_name[IFNAMSIZ];             /* interface name (e.g. "eth0") */
	struct ether_addr if_hwaddr;        /* interface hardware adress */
	unsigned int if_index;              /* interface index */
	unsigned int if_mtu;                /* interface MTU */
	int if_up;                          /* non-zero if interface is up */
	int if_loopback;                    /* non-zero if interface is a loopback device */
	int if_multicast;                   /* non-zero if interface supports multicasting */
};

/**
 * Get properties for an interface.
 * @param name Interface name, e.g. "eth0"
 * @param iface Pointer to a iface structure which will be filled with data.
 * @return 0 on success or errno on failure.
 */
int iface_get(const char* name, struct iface* iface);

#ifdef __cplusplus
}
#endif

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility pop
#endif

#endif /* CAPUTILS_INTERFACE_H */
