#ifndef CAPUTILS__STREAM_H
#define CAPUTILS__STREAM_H

#include <caputils/filter.h>
#include <caputils/capture.h>

#include <stdint.h>
#include <netinet/ether.h>

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
int stream_open(stream_t* stptr, const stream_addr_t* addr, const char* nic, size_t buffer_size);

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
unsigned int stream_num_addresses(const stream_t st);

/**
 * Print information about stream.
 */
void stream_print_info(const stream_t st, FILE* dst);

/**
 * Write a captured frame to a stream.
 */
int stream_write(stream_t st, const void* data, size_t size);

/**
 * Copy a capture packet into stream.
 * This a shorthand for `stream_write(st, head, sizeof(struct cap_header) + head->caplen)`.
 */
int stream_copy(stream_t st, const caphead_t head);

/**
 * Read the next matching frame from a stream.
 * @param st Stream to read from.
 * @param header Returns a pointer to the frame header (in the internal buffer).
 * @param filter If non-null, match frame against filter.
 * @param timeout See select(2) for description of timeout.
 * @return Zero if successful, -1 when finished, positive int on error. header is undefined on errors.
 */
int stream_read(stream_t st, cap_head** header, const struct filter* filter, struct timeval* timeout);

/**
 * Similar to stream_read but does not pop packet from stream.
 * @note If a filter is passed it _will_ discard non-matches, e.g. if you use
 *       stream_peek with filter and later call stream_read without you have
 *       lost the non-matches already.
 * @return same as stream_read. EAGAIN if there is no packet to read, there is no blocking version of this call.
 */
int stream_peek(stream_t st, cap_head** header, const struct filter* filter);

#ifdef __cplusplus
}
#endif

#endif /* CAPUTILS__STREAM_H */
