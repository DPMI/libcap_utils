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
struct stream{
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

  struct file_header FH;                //
  char *comment;                        //

  /* Callback functions */
  fill_buffer_callback fill_buffer;
  destroy_callback destroy;
};

int is_valid_version(struct file_header* fhptr);

int stream_udp_init(struct stream* st, const char* address, int port);
int stream_tcp_init(struct stream* st, const char* address, int port);
int stream_ethernet_init(struct stream* st, const char* address, const char* iface);
int stream_file_init(struct stream* st, const char* filename);

#endif /* CAPUTILS__STREAM_H */
