#ifndef CAPUTILS_UTILS_H
#define CAPUTILS_UTILS_H

#include <stdint.h>
#include <net/if.h>
#include <netinet/ether.h>

#ifndef IFHWADDRLEN
#define IFHWADDRLEN 6
#endif

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility push(default)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Text representation of error code.
 */
const char* caputils_error_string(int code);

typedef struct {
	int major;
	int minor;
	int micro;
	int features; /* bitmask, not yet implemented */
}	caputils_version_t;

/**
 * Get version from libcap_utils.
 * If version is non-null it fills the struct with data.
 * It returns a string containing the version (pointing to static memory)
 */
const char* caputils_version(caputils_version_t* version);

/**
 * Like ether_ntoa but does not omit leading zeros.
 */
const char* hexdump_address_r(const struct ether_addr* address, char buf[IFHWADDRLEN*3]);

/**
 * Like ether_ntoa but does not omit leading zeros. Returns a string to static memory.
 */
const char* hexdump_address(const struct ether_addr* addr);

/**
 * Wraps ether_aton and puts result in dst.
 * @return Zero if address is invalid and leaves dst is undefined.
 */
int eth_aton(struct ether_addr* dst, const char* addr);

struct ethertype {
	const char* name;
	uint16_t value;
};

const struct ethertype* ethertype_by_name(const char* name);
const struct ethertype* ethertype_by_number(int number);

#ifdef CAPUTILS_EXPORT
#pragma GCC visibility pop
#endif

#ifdef __cplusplus
}
#endif

#endif /* CAPUTILS_UTILS_H */
