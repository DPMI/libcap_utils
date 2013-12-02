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

#ifndef CAPUTILS_MARKER_H
#define CAPUTILS_MARKER_H

#include <stdint.h>
#include <caputils/capture.h>

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility push(default)
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
	MARKERPORT = 0x0811,
	MARKER_MAGIC = 0x9f7a3c83,
};

enum MarkerFlags {
	/* If termination flag is set capdump will close the current file and stop saving
	 * packets until it receives another marker. */
	MARKER_TERMINATE = (1<<0),
};

struct marker {
	uint32_t magic;
	uint8_t version;
	uint8_t flags;
	uint16_t reserved;

	uint32_t exp_id;
	uint32_t run_id;
	uint32_t key_id;
	uint32_t seq_num;
	uint64_t timestamp;
	char comment[64];

	/* timeval depttime; */
} __attribute__((packed));

/**
 * Test if packet is a marker packet.
 * If port is non-zero an additional test is made to ensure the marker was sent
 * on the given port. If zero the marker is searched for on any port. For
 * reliable usage a port should always be given.
 *
 * It returns the port the marker was detected on or 0 if packet wasn't a
 * marker. ptr is undefined if packet isn't a marker.
 */
int is_marker(const struct cap_header* cp, struct marker* ptr, int port);
int is_marker_udp(void* payload, struct marker* ptr, int port);

#ifdef __cplusplus
}
#endif

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility pop
#endif

#endif /* CAPUTILS_MARKER_H */
