#ifndef CAPUTILS_UTILS_H
#define CAPUTILS_UTILS_H

#include <net/if.h>
#include <netinet/ether.h>

#ifdef __cplusplus
extern "C" {
#endif

  /**
   * Text representation of error code.
   */
  const char* caputils_error_string(int code);
  
  /**
   * Like ether_ntoa but does not omit leading zeros.
   */
  const char* hexdump_address_r(const struct ether_addr* address, char buf[IFHWADDRLEN*3]);
  
  /**
   * Like ether_ntoa but does not omit leading zeros. Returns a string to static memory.
   */
  const char* hexdump_address(const struct ether_addr* addr);

#ifdef __cplusplus
}
#endif

#endif /* CAPUTILS_UTILS_H */
