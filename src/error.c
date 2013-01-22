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

#include "caputils/caputils.h"
#include "caputils_int.h"
#include <string.h>

static const char* errstr[ERROR_LAST - ERROR_FIRST] = {
	/* ERROR_FIRST */ NULL,

	/* ERROR_CAPFILE_INVALID   */ "not a valid capfile.",
	/* ERROR_CAPFILE_TRUNCATED */ "file is truncated.",
	/* ERROR_CAPFILE_FIFO_EXIST */ "filename already exists, ensure no other process is using this FIFO already",

	/* ERROR_INVALID_PROTOCOL */  "unsupported protocol",
	/* ERROR_INVALID_HWADDR */    "failed to parse hwaddr",
	/* ERROR_INVALID_MULTICAST */ "invalid address, expected multicast",
	/* ERROR_INVALID_IFACE */     "invalid interface",
	/* ERROR_BUFFER_LENGTH */     "read buffer must be greater than MTU",
	/* ERROR_BUFFER_MULTIPLE */   "buffer size must be a multiple of MTU",

	/* ERROR_NOT_IMPLEMENTED */   "feature not implemented.",
};

const char* caputils_error_string(int code){
	if ( code == -1 ){
		return "stream eof\n";
	} else if ( code & ERROR_FIRST ){
		return errstr[code^ERROR_FIRST];
	} else {
		return strerror(code);
	}
}
