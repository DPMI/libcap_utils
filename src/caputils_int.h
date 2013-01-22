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

#ifndef CAPUTILS_INT_H
#define CAPUTILS_INT_H

#include "caputils/caputils.h"
#include <netinet/ether.h>
#include <net/if.h>

#define CAPUTILS_FILE_MAGIC 0x8f1ae247c53d9b6e
#define LISTENPORT 0x0810

/**
 * Error enumerations.
 * The MSB decides if the codes is a regular errno or if it is a custom error.
 * 0: errno
 * 1: custom
 *
 * Use caputils_error_string to show error description.
 *
 * @note Remember to add the error description to error.c
 */
enum {
	NO_ERROR = 0,

	/* errno codes goes here */

	ERROR_FIRST = (1<<15),

	/* errors related to capfiles */
	ERROR_CAPFILE_INVALID,
	ERROR_CAPFILE_TRUNCATED,
	ERROR_CAPFILE_FIFO_EXIST,

	/* misc */
	ERROR_INVALID_PROTOCOL,
	ERROR_INVALID_HWADDR,
	ERROR_INVALID_MULTICAST,
	ERROR_INVALID_IFACE,
	ERROR_BUFFER_LENGTH,
	ERROR_BUFFER_MULTIPLE,

	ERROR_NOT_IMPLEMENTED, /* should not normally be used but during the transition period it is useful */

	ERROR_LAST
};

#endif /* CAPUTILS_INT_H */
