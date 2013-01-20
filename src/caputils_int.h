#ifndef CAPUTILS_INT_H
#define CAPUTILS_INT_H

#include "caputils/caputils.h"
#include <netinet/ether.h>
#include <net/if.h>

#define CAPUTILS_FILE_MAGIC 0x8f1ae247c53d9b6e
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

	ERROR_FIRST = (1<<15),

	/* errors related to capfiles */
	ERROR_CAPFILE_INVALID,
	ERROR_CAPFILE_TRUNCATED,
	ERROR_CAPFILE_FIFO_EXIST,

	/* misc */
	ERROR_INVALID_PROTOCOL,
	ERROR_INVALID_HWADDR,
	ERROR_INVALID_MULTICAST,
	ERROR_INVALID_IFACE,
	ERROR_BUFFER_LENGTH,
	ERROR_BUFFER_MULTIPLE,

	ERROR_NOT_IMPLEMENTED, /* should not normally be used but during the transition period it is useful */

	ERROR_LAST
};

#endif /* CAPUTILS_INT_H */
