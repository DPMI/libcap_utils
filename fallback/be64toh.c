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
#endif /* HAVE_CONFIG_H */

#include "be64toh.h"
#include <arpa/inet.h>

union bits {
	uint32_t v[2];
	uint64_t d;
};

uint64_t _int_htobe64(uint64_t host_64bits) {
	union bits out, in = { .d = host_64bits };

	out.v[1] = htonl(in.v[0]);
	out.v[0] = htonl(in.v[1]);

	return out.d;
}

uint64_t _int_be64toh(uint64_t big_endian_64bits){
	union bits out, in = { .d = big_endian_64bits };

	out.v[1] = ntohl(in.v[0]);
	out.v[0] = ntohl(in.v[1]);

	return out.d;
}
