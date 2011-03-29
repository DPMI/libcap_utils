#ifndef CAPUTILS__STREAM_H
#define CAPUTILS__STREAM_H

/* forward declare for callbacks */
struct stream;

/**
 * Fill the stream buffer.
 * @return Number of bytes actually read, zero if there is nothing more to read
 *         and negative on errors.
 */
typedef int (*fill_buffer_callback)(struct stream* st);

/**
 * Stream destructor.
 */
typedef int (*destroy_callback)(struct stream* st);

// Stream structure, used to manage different types of streams
//
//
struct stream {
  int type;                             // What type of stream do we have?
                                        // 0, a file
                                        // 1, ethernet multicast
                                        // 2, udp uni/multi-cast
                                        // 3, tcp unicast
  FILE *myFile;                         // File pointer
  
  int mySocket;                         // Socket descriptor  
  long expSeqnr;                        // Expected sequence number
  long pktCount;                        // Received packets
  char buffer[buffLen];                 // Buffer space
  int bufferSize;                       // Amount of data in buffer.
  int readPos;                          // Read position
  int flushed;                          // Indicate that we got a flush signal.

  char *address;                        // network address to listen, used when opening socket. 
  char *filename;                       // filename
  int portnr;                           // port number to listen to.
  int ifindex;                          // 
  int if_mtu;                           // The MTU of the interface reading udp/ethernet multicasts.

  struct file_header_t FH;                //
  char *comment;                        //

  /* Callback functions */
  fill_buffer_callback fill_buffer;
  destroy_callback destroy;
};

/**
 * Open an existing stream.
 * @return 1 if successful.
 */
int openstream(struct stream* myStream, const char* address, int protocol, const char* nic, int port);

/**
 * Create a new stream.
 */
int createstream(struct stream* myStream, const char *address, int protocol, const char* nic, const char* mpid, const char* comment);

/**
 * Create a filestream.
 * @param file A stream open for writing.
 * @return Zero on failures.
 */
int createstream_file(struct stream* st, FILE* file, const char* mpid, const char* comment);

/**
 * Close stream.
 */
int closestream(struct stream* myStream);

/**
 * Write a captured frame to a stream.
 */
int write_post(struct stream* myStream, u_char* data, int size);

/**
 * Read the next matching frame from a stream.
 * @param st Stream to read from
 * @param data Returns a pointer to the internal buffer for reading the frame.
 * @param filter Filter to match frames with.
 */
int read_post(struct stream* st, char** data, const struct filter*filter);

#endif /* CAPUTILS__STREAM_H */
