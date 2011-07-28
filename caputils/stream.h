#ifndef CAPUTILS__STREAM_H
#define CAPUTILS__STREAM_H

struct stream;

/**
 * Open an existing stream.
 * @return 1 if successful.
 */
long openstream(struct stream** stptr, const destination_t* dest, const char* nic, int port);

/**
 * Create a new stream.
 */
long createstream(struct stream** st, const destination_t* dest, const char* nic, const char* mpid, const char* comment);

/**
 * Create a filestream.
 * @param file A stream open for writing.
 * @return Zero on failures.
 */
long createstream_file(struct stream** stptr, FILE* file, const char* filename, const char* mpid, const char* comment);

/**
 * Close stream.
 */
long closestream(struct stream* st);

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
 * @param st Stream to read from
 * @param data Returns a pointer to the internal buffer for reading the frame.
 * @param filter Filter to match frames with.
 * @return Zero if successful, -1 when finished, positive int on error.
 */
long stream_read(struct stream* st, char** data, const struct filter* filter);

#endif /* CAPUTILS__STREAM_H */
