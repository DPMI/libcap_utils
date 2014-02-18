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
#include <string.h>

const char* methods[] = {
	"GET",
	"HEAD",
	"POST",
	"PUT",
	"DELETE",
	"TRACE",
	"OPTIONS",
	"PATCH",
	"HTTP/", /* response but works similar */
	NULL, /* sentinel */
};

static int min(int a, int b){ return a<b?a:b; }

void print_http(FILE* fp, const struct cap_header* cp, const char* payload, size_t size, unsigned int flags){
	const char** cur = methods;
	while ( *cur ){
		if ( strncmp(payload, *cur, min(strlen(*cur), size)) != 0 ){
			cur++;
			continue;
		}

		/* copy memory so it can be tokenized and ensures a null-terminator is present */
		char* buf = strndup(payload, size);
		char* line = strtok(buf, "\r\n");

		/* only print if the full request line is present */
		if ( line ){
			fprintf(fp, " %s", line);
		}

		free(buf);
		break;
	}
}
