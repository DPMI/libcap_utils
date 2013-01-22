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

#ifndef __WORKAROUND_BE64TOH_H
#define __WORKAROUND_BE64TOH_H

#include <stdint.h>

#ifdef HAVE_BE64TOH
#include <endian.h>
#else

#ifdef __cplusplus
extern "C" {
#endif

uint64_t htobe64(uint64_t val) __attribute__((weakref("_int_htobe64")));
uint64_t be64toh(uint64_t val) __attribute__((weakref("_int_be64toh")));

#ifdef __cplusplus
}
#endif

#endif /* HAVE_BE64TOH */

#endif /* __WORKAROUND_BE64TOH_H */
