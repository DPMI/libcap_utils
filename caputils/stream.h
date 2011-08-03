#ifndef CAPUTILS__STREAM_H
#define CAPUTILS__STREAM_H

#include <caputils/filter.h>

struct stream;

/**
 * Open an existing stream.
 * @return 1 if successful.
 */
long stream_open(struct stream** stptr, const destination_t* dest, const char* nic, int port);

/**
 * Create a new stream.
 */
long stream_create(struct stream** st, const destination_t* dest, const char* nic, const char* mpid, const char* comment);

/**
 * Create a filestream.
 * @param file A stream open for writing.
 * @return Zero on failures.
 */
//long createstream_file(struct stream** stptr, FILE* file, const char* filename, const char* mpid, const char* comment);

/**
 * Close stream.
 */
long stream_close(struct stream* st);

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
 * Write a captured frame to a stream.
 */
long stream_write(struct stream* st, const void* data, size_t size);

/**
 * Read the next matching frame from a stream.
 * @param st Stream to read from.
 * @param header Returns a pointer to the frame header (in the internal buffer).
 * @param filter If non-null, match frame against filter.
 * @return Zero if successful, -1 when finished, positive int on error. header is undefined on errors.
 */
long stream_read(struct stream* st, cap_head** header, const struct filter* filter);

#endif /* CAPUTILS__STREAM_H */
