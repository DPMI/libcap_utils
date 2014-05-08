/**
 * libcap_utils - DPMI capture utilities
 * Copyright (C) 2003-2014 (see AUTHORS)
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

#include "caputils/protocol.h"

#define REGISTER_PROTOCOL(x,y) \
	do { \
		if ( protocol_get(y) != NULL ){ \
			fprintf(stderr, "duplicate entry for " #y "\n"); \
			abort(); \
		} \
		extern struct caputils_protocol x; \
		protocol[y] = &x; \
	} while (0)

static struct caputils_protocol* protocol[PROTOCOL_NUM_AVAILABLE] = {0,};

struct caputils_protocol* protocol_get(enum caputils_protocol_type type){
	return protocol[type];
}

static void __attribute__((constructor)) protocol_init(void){
	REGISTER_PROTOCOL(protocol_data, PROTOCOL_DATA);
	REGISTER_PROTOCOL(protocol_done, PROTOCOL_DONE);
	REGISTER_PROTOCOL(protocol_ethernet, PROTOCOL_ETHERNET);
}
