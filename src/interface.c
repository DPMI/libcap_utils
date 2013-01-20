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

#include "caputils/interface.h"
#include "caputils/caputils.h"
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

int iface_get(const char* name, struct iface* iface){
	struct ifreq ifr;

	/* store the iface name */
	strncpy(ifr.ifr_name,   name, IFNAMSIZ);
	strncpy(iface->if_name, name, IFNAMSIZ);

	/* open socket */
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if ( fd < 0 ){
		return errno;
	}

	/* get iface index */
	if ( ioctl(fd, SIOCGIFINDEX, &ifr) == -1 ){
		return errno;
	}
	iface->if_index = ifr.ifr_ifindex;

	/* get iface MTU */
	if ( ioctl(fd, SIOCGIFMTU, &ifr) == -1 ){
		return errno;
	}
	iface->if_mtu = ifr.ifr_mtu;

	/* query interface flags */
	if ( ioctl(fd, SIOCGIFFLAGS, &ifr) == -1 ){
		return errno;
	}
	iface->if_up        = ifr.ifr_flags & IFF_UP;
	iface->if_loopback  = ifr.ifr_flags & IFF_LOOPBACK;
	iface->if_multicast = ifr.ifr_flags & IFF_MULTICAST;

	return 0;
}
