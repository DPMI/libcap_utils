#ifndef CAPUTILS_ADDRESS_H
#define CAPUTILS_ADDRESS_H

#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif

  struct stream_addr {
    union {
      /* raw buffer for backwards compability (may not be null-terminated) (includes old port) */
      unsigned char buffer[22 + 4];
      
      /* for ethernet streams */
      struct ether_addr ether_addr;
      
      /* for capfiles (null-terminated) */
      char filename[22];

      /* for locally stored capfiles (null-terminated) */
      /* these cannot be sent across network */
      const char* local_filename;
      
      /* for TCP/UDP streams */
      struct {
	struct in_addr in_addr;
	uint16_t in_port;
      };
    };

    uint16_t type;
    uint16_t flags;
  };
  typedef struct stream_addr stream_addr_t;

  enum AddressType {
    /**
     * If the format of the address isn't know, this flag can be set to have it
     * guess. Essentially it works like following:
     *  - If it is parsable as an ethernet address, STREAM_ADDR_ETHERNET is used.
     *  - If is begins with tcp:// or udp://, STREAM_ADD_{TCP,UDP} is used.
     *  - Otwerwise STREAM_ADDR_CAPFILE with STREAM_ADDR_LOCAL flag is used.
     *
     * However, if the user have a file which is named as an ethernet address
     * confusion might happen.
     */
    STREAM_ADDR_GUESS = -1,

    /* fixed format */
    STREAM_ADDR_CAPFILE = 0,
    STREAM_ADDR_ETHERNET,
    STREAM_ADDR_UDP,
    STREAM_ADDR_TCP,
  };

  enum AddressFlags {
    /* set to indicate that the capfile path is local (and can thus be longer
     * than a regular filename of 22 chars). Memory is referenced so the caller
     * must ensure the lifetime of the string is as long as the lifetime as the
     * filter holding this address. */
    STREAM_ADDR_LOCAL = (1<<0),
  };

  /**
   * Convert string to stream_addr_t.
   * @param dst Pointer to an existig destination_t.
   * @param src String representing an address.
   * @param type What kind of address it represents.
   * @param flags Special flags, can be set to zero. @see DestinationFlags.
   * @return Zero if successful, errno on errors.
   */
  int stream_addr_aton(stream_addr_t* dst, const char* src, enum AddressType type, int flags);

  /**
   * Convert destination to string. The string is returned in a statically
   * allocated buffer, which subsequent calls will overwrite.
   */
  const char* stream_addr_ntoa(const stream_addr_t* src);

  /**
   * Like destination_ntoa but writes into buf.
   * @param bytes Size of buf.
   */
  const char* stream_addr_ntoa_r(const stream_addr_t* src, char* buf, size_t bytes);

#ifdef __cplusplus
}
#endif

#endif /* CAPUTILS_ADDRESS_H */
