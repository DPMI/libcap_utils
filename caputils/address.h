#ifndef CAPUTILS_ADDRESS_H
#define CAPUTILS_ADDRESS_H

#include <stdio.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/**
 * Supported address format:
 *
 * Types:
 *  - ethernet address (hwaddr)
 *  - IP address:port
 *  - filename
 *
 * Ethernet address:
 *  - Optional but recommended colon or dash delimiter.
 *  - Can fill in blanks by using double color, e.g:
 *    01::01 is read as 01:00:00:00:00:01
 *
 * IP address:
 *  - tcp://127.0.0.1:4711
 *  - Supports tcp and udp.
 *  - Parsed using inet_aton.
 *
 * Filename:
 *  - Absolute or relative.
 *  - For filters limited to 22 chars.
 *  - No limit on local machine.
 *  - NOTE: For local addresses the string is referenced and must be retained
 *    during the lifetime of the address.
 *
 * To force a specific type use a prefix, e.g. file://127.0.0.1 reference a file
 * called "127.0.0.1". TCP/UDP is only supported using prefix.
 *
 */

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

	    /* used together with STREAM_ADDR_DUPLICATE */
	    char* int_filename;

	    /* Using existing FILE pointer. By default the user has to close this
	     * stream after stream_close. To automatically close it use
	     * STREAM_ADDR_FCLOSE flag. */
	    FILE* fp;

      /* for TCP/UDP streams */
      struct {
	      struct in_addr in_addr;
	      uint16_t in_port;
      };
    } __attribute__((packed));

    uint16_t _type;
    uint16_t _flags;
  } __attribute__((packed));
  typedef struct stream_addr stream_addr_t;

#define STREAM_ADDR_INITIALIZER {{{0,}},}

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
    STREAM_ADDR_FP,
    STREAM_ADDR_FIFO,
  };

  enum AddressFlags {
    /* set to indicate that the capfile path is local (and can thus be longer
     * than a regular filename of 22 chars). Memory is referenced so the caller
     * must ensure the lifetime of the string is as long as the lifetime as the
     * filter holding this address. */
    STREAM_ADDR_LOCAL = (1<<0),

    /* force the stream to be flushed for every write. useful for low-traffic
     * streams or to ensure real-time data. Not necessarily implemented for all
     * types.*/
    STREAM_ADDR_FLUSH = (1<<1),

    /* For files, FIFOs and similar, unlink the file in stream_close. This is
     * most useful for FIFO which is created dynamically and should not really
     * be used by end-users. */
    STREAM_ADDR_UNLINK = (1<<2),

    /* Normally the file is closed automatically but when using STREAM_ADDR_FP
     * that is not the case. Using this flag the FILE pointer will be closed
     * automatically. */
    STREAM_ADDR_FCLOSE = (1<<3),

    /* The local filename is duplicated and automatically freed. */
    STREAM_ADDR_DUPLICATE = (1<<4),
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
   * Set address to a local string (only referencing the memory)
   */
  int stream_addr_str(stream_addr_t* dst, const char* src, int flags);

  /**
   * Set address to an existing local file pointer. User must ensure it is open in the
   * correct mode for the operation.
   */
  int stream_addr_fp(stream_addr_t* dst, FILE* fp, int flags);

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

  enum AddressType stream_addr_type(const stream_addr_t* addr) __attribute__((pure));

  int stream_addr_flags(const stream_addr_t* addr) __attribute__((pure));

  int stream_addr_have_flag(const stream_addr_t* addr, enum AddressFlags flag);

  /**
   * Initialize address to zero.
   * Some address whose types allocates resources will be free'd.
   */
  void stream_addr_reset(stream_addr_t* addr);

  /**
   * Check if an address is set or not.
   */
  int stream_addr_is_set(const stream_addr_t* addr);

#ifdef __cplusplus
}
#endif

#endif /* CAPUTILS_ADDRESS_H */
