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

static void data_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	/* do nothing */
}

static void data_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	/* do nothing */
}

struct caputils_protocol protocol_done = {
	.name = "done",
	.next_payload = NULL,
	.format = NULL,
	.dump = NULL,
};

struct caputils_protocol protocol_data = {
	.name = "data",
	.next_payload = NULL,
	.format = data_format,
	.dump = data_dump,
};
