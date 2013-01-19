#ifndef CAPUTILS_INT_STREAM_H
#define CAPUTILS_INT_STREAM_H

#include <caputils/caputils.h>
#include <caputils/stream.h>

/**
 * Allocate and initialize a stream.
 *
 * @param size Size of concrete struct in bytes.
 * @param buffer_size Size of buffer in bytes. For write-only streams set to 0.
 * @param mtu Size of largest possible measurement frame we may receive.
 * @return Non-zero on failure.
 */
int stream_alloc(struct stream** st, enum protocol_t protocol, size_t size, size_t buffer_size, size_t mtu);

/**
 * Fill the stream buffer.
 * @param dst Destination buffer
 * @param max May write at most max bytes.
 * @return Number of bytes actually read, zero if there is nothing more to read
 *         and negative on errors.
 */
typedef int (*fill_buffer_callback)(struct stream* st, struct timeval* timeout, char* dst, size_t max);

/**
 * Stream destructor.
 */
typedef long (*destroy_callback)(struct stream* st);

typedef int (*write_callback)(struct stream* st, const void* data, size_t size);

typedef int (*read_callback)(struct stream* st, cap_head** header, const struct filter* filter, struct timeval* timeout);

typedef int (*flush_callback)(struct stream* st);

// Stream structure, used to manage different types of streams
struct stream {
	enum protocol_t type;                 // What type of stream do we have?
	stream_addr_t addr;                   // The address used to open stream.

	/* header related */
	struct file_header_t FH;
	char *comment;

	/* common fields */
	char* buffer;
	size_t buffer_size;                   // Total size of the buffer
	unsigned long expSeqnr;               // Expected sequence number
	unsigned int writePos;                // Write position
	unsigned int readPos;                 // Read position
	int flushed;                          // Indicate that we got a flush signal.
	unsigned int num_addresses;           // Number of addresses associated with stream
	size_t if_mtu;                        // Interface MTU (size of the largest measurement frame we may receive on this interface)
	int if_loopback;                      // Set to non-zero if the stream is a loopback interface.

	/* stats */
	struct stream_stat stat;

	/* Callback functions */
	fill_buffer_callback fill_buffer;
	destroy_callback destroy;
	write_callback write;
	read_callback read;
	flush_callback flush;
};

int is_valid_version(struct file_header_t* fhptr);

/**
 * Check and increment sequencenumber.
 * prints to stderr on mismatch.
 */
void match_inc_seqnr(const struct stream* st, long unsigned int* restrict seq, const struct sendhead* restrict sh);

int stream_udp_create(stream_t* st, const struct sockaddr_in* addr, int flags);
int stream_udp_open(stream_t* st, const struct sockaddr_in* addr);
int stream_udp_add(stream_t stt, const struct in_addr addr);
int stream_tcp_init(struct stream* st, const char* address, int port);

#ifdef HAVE_PFRING
long stream_pfring_open(struct stream** stptr, const struct ether_addr* addr, const char* iface, size_t buffer_size);
long stream_pfring_create(struct stream** stptr, const struct ether_addr* address, const char* iface, const char* mpid, const char* comment, int flags);
long stream_pfring_add(struct stream* st, const struct ether_addr* addr);
#else
long stream_ethernet_open(struct stream** stptr, const struct ether_addr* address, const char* iface, size_t buffer_size);
long stream_ethernet_create(struct stream** stptr, const struct ether_addr* address, const char* iface, const char* mpid, const char* comment, int flags);
long stream_ethernet_add(struct stream* st, const struct ether_addr* addr);
#endif

/**
 * @param fp Optional, if null filename is used.
 */
int stream_file_open(struct stream** stptr, FILE* fp, const char* filename, size_t buffer_size);

/**
 * @param fp Optional, if null filename is used.
 */
int stream_file_create(struct stream** stptr, FILE* fp, const char* filename, const char* mpid, const char* comment, int flags);

#endif /* CAPUTILS_INT_STREAM_H */
