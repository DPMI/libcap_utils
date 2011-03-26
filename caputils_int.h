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

#endif /* CAPUTILS_INT_H */
