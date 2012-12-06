#ifndef CAPUTILS_INT_H
#define CAPUTILS_INT_H

#include "caputils/caputils.h"
#include <netinet/ether.h>
#include <net/if.h>

/**
 * Wraps ether_aton and puts result in dst.
 * @return Zero if address is invalid and leaves dst is undefined.
 */
int eth_aton(struct ether_addr* dst, const char* addr);

#define CAPUTILS_FILE_MAGIC 0x8f1ae247c53d9b6e
#define MARKER_MAGIC 0x9f7a3c83
#define LISTENPORT 0x0810
#define MARKERPORT 0x0811

/**
 * Error enumerations.
 * The MSB decides if the codes is a regular errno or if it is a custom error.
 * 0: errno
 * 1: custom
 *
 * Use caputils_error_string to show error description.
 *
 * @note Remember to add the error description to error.c
 */
enum {
  NO_ERROR = 0,

  /* errno codes goes here */

  ERROR_FIRST = (1<<15),

  /* errors related to capfiles */
  ERROR_CAPFILE_INVALID,
  ERROR_CAPFILE_TRUNCATED,
  ERROR_CAPFILE_FIFO_EXIST,

  /* misc */
  ERROR_INVALID_PROTOCOL,
  ERROR_INVALID_HWADDR,
  ERROR_INVALID_HWADDR_MULTICAST,
  ERROR_INVALID_IFACE,
  ERROR_BUFFER_LENGTH,
  ERROR_BUFFER_MULTIPLE,

  ERROR_NOT_IMPLEMENTED, /* should not normally be used but during the transition period it is useful */

  ERROR_LAST
};

int is_valid_version(struct file_header_t* fhptr);

/**
 * Check and increment sequencenumber.
 * prints to stderr on mismatch.
 */
void match_inc_seqnr(const struct stream* st, long unsigned int* restrict seq, const struct sendhead* restrict sh);

int stream_udp_init(struct stream* st, const char* address, int port);
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

#endif /* CAPUTILS_INT_H */
