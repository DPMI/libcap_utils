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

#include "format.h"

static uint32_t adler32(const unsigned char *data, size_t len){
	const int MOD_ADLER = 65521;
	uint32_t a = 1, b = 0;

	for ( unsigned int i = 0; i < len; i++ ){
		a = (a + data[i]) % MOD_ADLER;
		b = (b + a) % MOD_ADLER;
	}

	return (b << 16) | a;
}

void print_mp(FILE* dst, const struct cap_header* cp, const struct sendhead* send){
	fprintf(dst, " MP packet [seqnum=%04x, nopkts: %d]", ntohl(send->sequencenr), ntohl(send->nopkts));
}

void print_mp_diagnostic(FILE* dst, const struct cap_header* cp, const char* data){
	struct meta {
		uint8_t version;
		uint8_t reserved[3];
		uint32_t mtu;
		uint32_t size;
		uint32_t len;
		uint32_t checksum;
		unsigned char payload[];
	} __attribute__((packed)) const* meta = (const struct meta*)data;

	const uint32_t len = ntohl(meta->len);
	const uint32_t expected = ntohl(meta->checksum);
	const uint32_t actual   = adler32(meta->payload, len);

	fprintf(dst, " MP diagnostic packet v%d: data size: %d, checksum ", meta->version, len);

	if ( expected == actual ){
		fprintf(dst, "OK");
	} else {
		fprintf(dst, "FAILED (got %08x, expected %08x)", actual, expected);
	}
}
