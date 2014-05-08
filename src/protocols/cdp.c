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

#include "src/format/format.h"
#include "caputils/caputils.h"

static enum caputils_protocol_type cdp_next(struct header_chunk* header, const char* ptr, const char** out){
	return PROTOCOL_DONE;
}

static void cdp_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	fprintf(fp, ": Cisco-Discovery-Protocol");
}

static void cdp_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){

}

struct caputils_protocol protocol_cdp = {
	.name = "CDP",
	.size = 0,
	.partial_print = 0,
	.next_payload = cdp_next,
	.format = cdp_format,
	.dump = cdp_dump,
};
