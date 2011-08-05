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

/**
 * Initialize variables for a stream.
 * @bug To retain compability with code, some variables which weren't
 *      initialized are left that way, at least until I proved and tested it
 *      does not break.
 * @return Non-zero on failure.
 */
int stream_alloc(struct stream** st, enum protocol_t protocol, size_t size);

#define CAPUTILS_FILE_MAGIC 0x8f1ae247c53d9b6e
#define LLPROTO 0x0810
#define LISTENPORT 0x0810

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

  __UNUSED = 0x80000000,

  /* errors related to capfiles */
  ERROR_CAPFILE_INVALID,
  ERROR_CAPFILE_TRUNCATED,

  /* misc */
  ERROR_INVALID_PROTOCOL,
  ERROR_INVALID_HWADDR,
  ERROR_INVALID_HWADDR_MULTICAST,
  ERROR_INVALID_IFACE,
  ERROR_NOT_IMPLEMENTED, /* should not normally be used but during the transition period it is useful */

  MAX_ERRORS
};

int is_valid_version(struct file_header_t* fhptr);

/**
 * Check and increment sequencenumber.
 * prints to stderr on mismatch.
 */
void match_inc_seqnr(struct stream* restrict st, const struct sendhead* restrict sh);

int stream_udp_init(struct stream* st, const char* address, int port);
int stream_tcp_init(struct stream* st, const char* address, int port);

long stream_ethernet_open(struct stream** stptr, const struct ether_addr* address, const char* iface);
long stream_ethernet_create(struct stream** stptr, const struct ether_addr* address, const char* iface, const char* mpid, const char* comment);

long stream_file_open(struct stream** stptr, const char* filename);

/**
 * @param fp Optional
 */
int stream_file_create(struct stream** stptr, FILE* fp, const char* filename, const char* mpid, const char* comment);

#endif /* CAPUTILS_INT_H */
