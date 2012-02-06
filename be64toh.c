#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "be64toh.h"
#include <arpa/inet.h>

union bits {
	uint32_t v[2];
	uint64_t d;
};

#ifndef HAVE_BE64TOH
void htobe64() __attribute__((weak, alias ("_int_htobe64")));
void be64toh() __attribute__((weak, alias ("_int_be64toh")));
#endif

uint64_t _int_htobe64(uint64_t host_64bits) {
	union bits out, in = { .d = host_64bits };

	out.v[1] = htonl(in.v[0]);
	out.v[0] = htonl(in.v[1]);

	return out.d;
}

uint64_t _int_be64toh(uint64_t big_endian_64bits){
	union bits out, in = { .d = big_endian_64bits };

	out.v[1] = ntohl(in.v[0]);
	out.v[0] = ntohl(in.v[1]);

	return out.d;
}
