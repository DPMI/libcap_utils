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

/**
 * Compile with:
 * gcc -Wall example/03-traversing-headers.c $(pkg-config libcap_utils-0.7 --libs) -o 03-traversing-headers
 */

#include "caputils/caputils.h"
#include "caputils/packet.h"
#include <stdio.h>
#include <netinet/tcp.h>

static void handle_tcp(const cap_head* cp, const struct header_chunk* header, const struct tcphdr* tcp){
	const size_t header_size = 4*tcp->doff;
	const size_t payload_size = header->last_net.plen - header_size;
	fprintf(stdout, "Got a TCP packet from %s:%d to %s:%d with a %zd byte payload\n",
	        header->last_net.net_src, ntohs(tcp->source),
	        header->last_net.net_dst, ntohs(tcp->dest),
	        payload_size);
}

static int handle_packet(const stream_t st, const cap_head* cp){
	/* initialize walker */
	struct header_chunk header;
	header_init(&header, cp, 0);

	/* traverse each header */
	while ( header_walk(&header) ){
		switch ( header.protocol->type ){
		case PROTOCOL_ETHERNET:
			/* ... */
			break;

		case PROTOCOL_IPV4:
			/* ... */
			break;

		/* for an up-to-date list of supported protocols see caputiles/protocol.h */

		case PROTOCOL_TCP:
			handle_tcp(cp, &header, (const struct tcphdr*)header.ptr);
			return 0; /* stop traversing once a TCP header is found */

		case PROTOCOL_UNKNOWN: /* the next header could not be read for an unknown reason */
		case PROTOCOL_DATA:    /* the previous header indicated that the rest of the packet is payload only, i.e. there will be no more headers for this packet */
		case PROTOCOL_DONE:    /* the previous header had no payload */
		default:
			break;
		}
	}

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
