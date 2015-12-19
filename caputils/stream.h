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

#ifndef CAPUTILS_STREAM_H
#define CAPUTILS_STREAM_H

#include <caputils/filter.h>
#include <caputils/capture.h>

#include <stdint.h>
#include <netinet/ether.h>

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility push(default)
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct stream;
typedef struct stream* stream_t;

struct stream_stat {
	uint64_t recv;     /* number of packets read into buffer */
	uint64_t read;     /* number of packets user (tried to) read, that is, before filtering */
	uint64_t matched;  /* number of packets matched filter */

	uint64_t buffer_size;  /* size of buffer in bytes */
	uint64_t buffer_usage; /* number of bytes used */
};
typedef struct stream_stat stream_stat_t;

/**
 * Open an existing stream.
 *
 * @param stptr Pointer to a stream handle.
 * @param addr Stream address to open.
 * @param iface For ethernet streams it is the interface it listen on (only used for ethernet, can be null)
 * @param buffer_size Buffer size in bytes, use 0 for default.
 * @return 0 if successful or error code on errors (use caputils_error_string to get description)
 */
int stream_open(stream_t* stptr, const stream_addr_t* addr, const char* iface, size_t buffer_size);

/**
 * Create a new stream.
 */
int stream_create(stream_t* st, const stream_addr_t* addr, const char* nic, const char* mpid, const char* comment);

/**
 * Add source to stream (currently only for ethernet multicast)
 * @return 0 if successful.
 * @errors
 *   EINVAL
 *     Invalid stream or addr is not ethernet multicast.
 *   ERROR_INVALID_PROTOCOL
 *     Stream is not ethernet multicast.
 */
int stream_add(stream_t st, const stream_addr_t* addr);

/**
 * Shorthand for opening multiple streams from command-line arguments.
 * Calls stream_open followed by stream_add, with error checking. Errors is
 * printed on stderr.
 *
 * @param st Stream
 * @param argv
 * @param argc
 * @param optind
 * @param iface Ethernet interface to use for ethernet streams.
 * @param defaddr Default address to use if no address was specified or NULL to
 *                raise an error. Use "-" for stdin (which will ensure it is not
 *                connected to a terminal)
 * @param program_name
 * @param buffer_size Buffer size in bytes or 0 for default.
 */
int stream_from_getopt(stream_t* st,
                       char* argv[], int optind, int argc,
                       const char* iface, const char* defaddr,
                       const char* program_name, size_t buffer_size);

/**
 * Close stream.
 * It is safe to call on a stream which hasn't been opened. You should set st to NULL after calling.
 */
int stream_close(stream_t st);

/**
 * Get verion of this stream.
 */
void stream_get_version(const stream_t st, struct file_version* dst);

/**
 * Get stream comment.
 * @return Internal reference to comment.
 */
const char* stream_get_comment(const stream_t st);

/**
 * Get MAMPid of stream or NULL if unknown.
 * @return Internal reference to MAMPid.
 */
const char* stream_get_mampid(const stream_t st);

/**
 * Read stats from stream.
 * Returns internal structure, don't need to call repeated and don't free it.
 */
const struct stream_stat* stream_get_stat(const stream_t st);

/**
 * Get number of addresses associated with this stream.
 */
unsigned int stream_num_address(const stream_t st);

/**
 * Print information about stream.
 */
void stream_print_info(const stream_t st, FILE* dst);

/**
 * Write a captured frame to a stream.
 * @param size size of data (including caphead)
 */
int stream_write(stream_t st, const void* data, size_t size);

/**
 * Similar to stream_write but with caphead and payload from separate buffers.
 * Should only be used with capfiles.
 * @param size size of payload in bytes
 */
int stream_write_separate(stream_t st, const caphead_t head, const void* data, size_t size);

/**
 * Copy a capture packet into stream.
 * This a shorthand for `stream_write(st, head, sizeof(struct cap_header) + head->caplen)`.
 */
int stream_copy(stream_t st, const struct cap_header* head);

/**
 * Read the next matching frame from a stream.
 * @param st Stream to read from.
 * @param header Returns a pointer to the frame header (in the internal buffer).
 * @param filter If non-null, match frame against filter.
 * @param timeout See select(2) for description of timeout.
 * @return Zero if successful, -1 when finished, positive int on error. header is undefined on errors.
 */
int stream_read(stream_t st, cap_head** header, struct filter* filter, struct timeval* timeout);

/**
 * Read packets until stream ends or interrupted. Apply callback on captured
 * packet.
 *
 * Should be called in a simple loop until it returns non-zero. This function
 * primary deals with the error conditions from stream_read and ensures the
 * callers application can terminate properly given signals such as SIGINT.
 *
 * @param st Stream to read from.
 * @param filter If non-null, match frame against filter.
 * @param callback Function to call for each packet.
 * @param timeout See select(2) for description of timeout.
 * @return Callback return value if successful, -1 when finished, positive int on error.
 */
typedef int (*stream_read_callback_t)(const stream_t st, const cap_head* cp);
int stream_read_cb(stream_t st, struct filter* filter, stream_read_callback_t callback, const struct timeval* timeout);

/**
 * Similar to stream_read but does not pop packet from stream.
 * @note If a filter is passed it _will_ discard non-matches, e.g. if you use
 *       stream_peek with filter and later call stream_read without you have
 *       lost the non-matches already.
 * @return same as stream_read. EAGAIN if there is no packet to read, there is no blocking version of this call.
 */
int stream_peek(stream_t st, cap_head** header, struct filter* filter);

/**
 * Force flushing of output stream. Most usable with capfiles.
 */
int stream_flush(stream_t st);

#ifdef __cplusplus
}
#endif

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility pop
#endif

#endif /* CAPUTILS_STREAM_H */
