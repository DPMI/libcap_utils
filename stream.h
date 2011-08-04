#ifndef CAPUTILS_INT_STREAM_H
#define CAPUTILS_INT_STREAM_H

#include <caputils/stream.h>

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

typedef int (*write_callback)(struct stream* st, const void* data, size_t size);

// Stream structure, used to manage different types of streams
struct stream {
  enum protocol_t type;                 // What type of stream do we have?

  /* header related */
  struct file_header_t FH;
  char *comment;

  /* common fields */
  char* buffer;
  unsigned long expSeqnr;               // Expected sequence number
  unsigned long pktCount;               // Received packets
  unsigned int bufferSize;              // Amount of data in buffer.
  unsigned int readPos;                 // Read position
  int flushed;                          // Indicate that we got a flush signal.

  /* Callback functions */
  fill_buffer_callback fill_buffer;
  destroy_callback destroy;
  write_callback write;
};

#endif /* CAPUTILS_INT_STREAM_H */
