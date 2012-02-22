#ifndef CAPUTILS__STREAM_H
#define CAPUTILS__STREAM_H

#include <caputils/filter.h>

#include <stdint.h>
#include <netinet/ether.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stream;
typedef struct stream stream_t;

struct stream_stat {
	uint64_t recv;     /* number of packets read into buffer */
	uint64_t read;     /* number of packets user (tried to) read, that is, before filtering */
	uint64_t matched;  /* number of packets matched filter */
};
typedef struct stream_stat stream_stat_t;

/**
 * Open an existing stream.
 * @return 1 if successful.
 */
int stream_open(struct stream** stptr, const stream_addr_t* addr, const char* nic, int port);

/**
 * Create a new stream.
 */
int stream_create(struct stream** st, const stream_addr_t* addr, const char* nic, const char* mpid, const char* comment);

/**
 * Create a filestream.
 * @param file A stream open for writing.
 * @return Zero on failures.
 */
//int createstream_file(struct stream** stptr, FILE* file, const char* filename, const char* mpid, const char* comment);

/**
 * Add source to stream (currently only for ethernet multicast)
 * @return 0 if successful.
 * @errors
 *   EINVAL
 *     Invalid stream or addr is not ethernet multicast.
 *   ERROR_INVALID_PROTOCOL
 *     Stream is not ethernet multicast.
 */
int stream_add(struct stream* st, const stream_addr_t* addr);

/**
 * Close stream.
 */
int stream_close(struct stream* st);

/**
 * Get verion of this stream.
 */
void stream_get_version(const struct stream* st, struct file_version* dst);

/**
 * Get stream comment.
 * @return Internal reference to comment.
 */
const char* stream_get_comment(const struct stream* st);

/**
 * Get MAMPid of stream or NULL if unknown.
 * @return Internal reference to MAMPid.
 */
const char* stream_get_mampid(const struct stream* st);

/**
 * Read stats from stream.
 * Returns internal structure, don't need to call repeated and don't free it.
 */
const struct stream_stat* stream_get_stat(const struct stream* st);

/**
 * Write a captured frame to a stream.
 */
int stream_write(struct stream* st, const void* data, size_t size);

/**
 * Read the next matching frame from a stream.
 * @param st Stream to read from.
 * @param header Returns a pointer to the frame header (in the internal buffer).
 * @param filter If non-null, match frame against filter.
 * @param timeout See select(2) for description of timeout.
 * @return Zero if successful, -1 when finished, positive int on error. header is undefined on errors.
 */
int stream_read(struct stream* st, cap_head** header, const struct filter* filter, struct timeval* timeout);

#ifdef __cplusplus
}
#endif

#endif /* CAPUTILS__STREAM_H */
