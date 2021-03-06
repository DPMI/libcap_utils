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

#ifndef CAPUTILS_UTILS_H
#define CAPUTILS_UTILS_H

#include <stdint.h>
#include <net/if.h>
#include <netinet/ether.h>

#ifndef IFHWADDRLEN
#define IFHWADDRLEN 6
#endif

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility push(default)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Text representation of error code.
 */
const char* caputils_error_string(int code);

/**
 * Like ether_ntoa but does not omit leading zeros.
 */
const char* hexdump_address_r(const struct ether_addr* address, char buf[IFHWADDRLEN*3]);

/**
 * Like ether_ntoa but does not omit leading zeros. Returns a string to static memory.
 */
const char* hexdump_address(const struct ether_addr* addr);

/**
 * Wraps ether_aton and puts result in dst.
 * @return Zero if address is invalid and leaves dst is undefined.
 */
int eth_aton(struct ether_addr* dst, const char* addr);

struct ethertype {
	const char* name;
	uint16_t value;
};

const struct ethertype* ethertype_by_name(const char* name);
const struct ethertype* ethertype_by_number(int number);

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility pop
#endif

#ifdef __cplusplus
}
#endif

#endif /* CAPUTILS_UTILS_H */
