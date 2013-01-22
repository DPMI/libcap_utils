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

#ifndef CAPUTILS_FILE_H
#define CAPUTILS_FILE_H

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility push(default)
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Struct with the version of this libraryfile
// A simple structure used to store a version number.
// The number is divided into a major and minor number.
struct file_version{
	uint16_t major;
	uint16_t minor;
};

// File header, when a cap file is stored to disk. This header is placed first.
// The header has two parts, header and comment. After the comment the frames
// are stored.
struct file_header_t {
	/* Magic number to identify capfiles. (nowadays 8 bytes are recommended due to
	 * the large number of formats available). */
	uint64_t magic;

	/*  What version was used to store this file */
	struct file_version version;

	/* sizeof(header) so future revisions of this header can be made without
	 * breaking older files too much. E.g fill in missing fields based on version
	 * and seek to the right location. */
	uint16_t header_offset;

	/* Length of the comment string */
	uint16_t comment_size;

	/* MP(s) ID */
	char mpid[200];
};

struct file_header_06 {
	uint32_t comment_size;
	struct {
		uint8_t major;
		uint8_t minor;
	} version;
	char mpid[200];
};

struct file_header_05 {
	uint32_t comment_size;
	struct {
		uint32_t major;
		uint32_t minor;
	} version;
	char mpid[200];
};

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility pop
#endif

#ifdef __cplusplus
}
#endif

#endif /* CAPUTILS_FILE_H */
