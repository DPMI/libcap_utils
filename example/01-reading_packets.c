/**
 * libcap_utils - DPMI capture utilities
 * Copyright (C) 2003-2015 (see AUTHORS)
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

#include "caputils/caputils.h"
#include <stdio.h>

static int handle_packet(const stream_t st, const cap_head* cp){
	fprintf(stdout, "Got a %d byte packet\n", cp->len);
	return 0;
}

int main(int argc, char **argv){
	int ret;

	/* validate arguments */
	if ( argc != 2 ){
		fprintf(stderr, "usage: %s FILENAME\n", argv[0]);
		return 1;
	}

	/* load tracefile address */
	const char* filename = argv[1];
	stream_addr_t addr = STREAM_ADDR_INITIALIZER;
	stream_addr_str(&addr, filename, 0);

	/* open stream */
	stream_t stream;
	if ( (ret=stream_open(&stream, &addr, NULL, 0)) != 0 ){
		fprintf(stderr, "%s: %s\n", filename, caputils_error_string(ret));
		return ret;
	}

	/* read packets */
	while ( stream_read_cb(stream, handle_packet, NULL, NULL) == 0 );

	/* close stream */
	stream_close(stream);

	return 0;
}
