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
#include "caputils/utils.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

static const char* yesno(int x){ return x ? "yes" : "no"; }

int main(int argc, const char* argv[]){
	struct iface iface;
	int ret;

	if ( argc < 2 ){
		fprintf(stderr, "usage: ifstat IFACE\n");
		fprintf(stderr, "Displays information about network interface.\n");
		return 1;
	}

	if ( (ret=iface_get(argv[1], &iface)) != 0 ){
		fprintf(stderr, "ifstat: %s\n", strerror(ret));
		return 1;
	}

	fprintf(stdout, "     if_name: %s\n", iface.if_name);
	fprintf(stdout, "   if_hwaddr: %s\n", hexdump_address(&iface.if_hwaddr));
	fprintf(stdout, "    if_index: %d\n", iface.if_index);
	fprintf(stdout, "      if_mtu: %d\n", iface.if_mtu);
	fprintf(stdout, "       if_up: %s\n", yesno(iface.if_up));
	fprintf(stdout, " if_loopback: %s\n", yesno(iface.if_loopback));
	fprintf(stdout, "if_multicast: %s\n", yesno(iface.if_multicast));

	return 0;
}
