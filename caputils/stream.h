#ifndef CAPUTILS__STREAM_H
#define CAPUTILS__STREAM_H

/**
 * Fill the stream buffer.
 * @return Number of bytes actually read, zero if there is nothing more to read
 *         and negative on errors.
 */
typedef int (*fill_buffer_callback)(struct stream* st, struct timeval* timeout);

/**
 * Stream destructor.
 */
typedef long (*destroy_callback)(struct stream* st);

typedef int (*write_callback)(struct stream* st, u_char* data, size_t size);

// Stream structure, used to manage different types of streams
//
//
struct stream {
  enum protocol_t type;                 // What type of stream do we have?

  /* header related */
  struct file_header_t FH;
  char *comment;

  /* common fields */
  char* buffer;
  long expSeqnr;                        // Expected sequence number
  long pktCount;                        // Received packets
  int bufferSize;                       // Amount of data in buffer.
  int readPos;                          // Read position
  int flushed;                          // Indicate that we got a flush signal.

  /* Callback functions */
  fill_buffer_callback fill_buffer;
  destroy_callback destroy;
  write_callback write;
};

/**
 * Open an existing stream.
 * @return 1 if successful.
 */
long openstream(struct stream** stptr, const char* address, enum protocol_t protocol, const char* nic, int port);

/**
 * Create a new stream.
 */
long createstream(struct stream** st, const char* address, int protocol, const char* nic, const char* mpid, const char* comment);

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
 * Write a captured frame to a stream.
 */
long write_post(struct stream* myStream, u_char* data, int size);

/**
 * Read the next matching frame from a stream.
 * @param st Stream to read from
 * @param data Returns a pointer to the internal buffer for reading the frame.
 * @param filter Filter to match frames with.
 * @return Zero if successful, -1 when finished, positive int on error.
 */
long read_post(struct stream* st, char** data, const struct filter*filter);

#endif /* CAPUTILS__STREAM_H */
