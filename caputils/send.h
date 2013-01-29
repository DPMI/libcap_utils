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

#ifndef CAPUTILS_SEND_H
#define CAPUTILS_SEND_H

#include <caputils/file.h>

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility push(default)
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Send Structure, used infront of each send data packet. The sequence number is indicates the number
// of sent data packets. I.e. after a send packet this value is increased by one.
struct sendhead {
	uint32_t sequencenr;                  // Sequence number.
	uint32_t nopkts;                      // How many packets are here.
	uint32_t flush;                       // Indicate that this is the last packet.
	struct file_version version;          // What version of the file format is used for storing mp_pkts.
};

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility pop
#endif

#ifdef __cplusplus
}
#endif

#endif /* CAPUTILS_SEND_H */
