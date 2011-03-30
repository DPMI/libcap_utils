#ifndef CAPUTILS_INT_H
#define CAPUTILS_INT_H

#include <netinet/ether.h>
/**
 * Check if a frame matches filter.
 * @return Non-zero if frame matches filter.
 */
int checkFilter(const char* pkt, const struct filter* filter);

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
  ERROR_NOT_IMPLEMENTED, /* should not normally be used but during the transition period it is useful */

  MAX_ERRORS
};

int is_valid_version(struct file_header_t* fhptr);

int stream_udp_init(struct stream* st, const char* address, int port);
int stream_tcp_init(struct stream* st, const char* address, int port);
int stream_ethernet_init(struct stream* st, const char* address, const char* iface);

int stream_file_open(struct stream** stptr, const char* filename);

/**
 * @param fp Optional
 */
int stream_file_create(struct stream** stptr, FILE* fp, const char* filename, const char* mpid, const char* comment);

#endif /* CAPUTILS_INT_H */
