#ifndef CAPUTILS_FILTER_H
#define CAPUTILS_FILTER_H

#include <caputils/capture.h>
#include <caputils/picotime.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif

  typedef char CI_handle_t[8];

  struct destination {
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
  typedef struct destination destination_t;

  enum DestinationType {
    DEST_CAPFILE = 0,
    DEST_ETHERNET,
    DEST_UDP,
    DEST_TCP,
  };

  enum DestinationFlags {
    /* set to indicate that the capfile path is local (and can thus be longer
     * than a regular filename of 22 chars) */
    DEST_LOCAL = (1<<0),
  };

  enum FilterBitmask {
    /* filter 0.7 extensions */
    FILTER_START_TIME=(1<<12),
    FILTER_END_TIME = (1<<11),
    FILTER_MAMPID   = (1<<10),

    /* original */
    FILTER_CI       = (1<<9), /* alias for FILTER_IFACE */
    FILTER_IFACE    = (1<<9),
    FILTER_VLAN     = (1<<8),
    FILTER_ETH_TYPE = (1<<7),
    FILTER_ETH_SRC  = (1<<6),
    FILTER_ETH_DST  = (1<<5),
    FILTER_IP_PROTO = (1<<4),
    FILTER_IP_SRC   = (1<<3),
    FILTER_IP_DST   = (1<<2),
    FILTER_SRC_PORT = (1<<1),
    FILTER_DST_PORT = (1<<0),
  };

  /* Filter Structure */
#define LIBMARC_FILTER_DEF						\
  /* Integer identifying the rule. This should be uniqe for the MP. */	\
  uint32_t filter_id;							\
									\
  /* Which fields should we check? Bitmask (see further fields for values) */ \
  uint32_t index;							\
  CI_handle_t iface;                 /* 512: Which CI */                \
  uint16_t vlan_tci;                 /* 256: VLAN id */			\
  uint16_t eth_type;                 /* 128: Ethernet type */		\
  struct ether_addr eth_src;         /*  64: Ethernet Source */		\
  struct ether_addr eth_dst;         /*  32: Ethernet Destination */	\
  uint8_t ip_proto;                  /*  16: IP Payload Protocol */	\
  unsigned char _ip_src[16];         /* DO NOT USE. FOR COMPAT ONLY */  \
  unsigned char _ip_dst[16];         /* DO NOT USE: FOR COMPAT ONLY */  \
  uint16_t src_port;                 /*   2: Transport Source Port */	\
  uint16_t dst_port;                 /*   1: Transport Destination Port */ \
									\
  uint16_t vlan_tci_mask;            /* VLAN id mask */			\
  uint16_t eth_type_mask;            /* Ethernet type mask */		\
  struct ether_addr eth_src_mask;    /* Ethernet Source Mask */		\
  struct ether_addr eth_dst_mask;    /* Ethernet Destination Mask */	\
  unsigned char _ip_src_mask[16];    /* DO NOT USE. FOR COMPAT ONLY */  \
  unsigned char _ip_dst_mask[16];    /* DO NOT USE. FOR COMPAT ONLY */  \
  uint16_t src_port_mask;            /* Transport Source Port Mask */	\
  uint16_t dst_port_mask;            /* Transport Destination Port Mask */ \
  uint32_t consumer;                 /* Destination Consumer */		\
  uint32_t caplen;                   /* Amount of data to capture. */	\
									\
  destination_t dest;                /* Destination. */			\
                                                                        \
  /* filter 0.7 extensions */                                           \
  uint32_t version;                  /* filter version */		\
  timepico starttime;                /* 4096: Time of first packet. */  \
  timepico endtime;                  /* 2048: Time of last packet. */   \
  char mampid[8];                    /* 1024: Match MAMPid */           \
  struct in_addr ip_src;             /*    8: IP source */              \
  struct in_addr ip_src_mask;                                           \
  struct in_addr ip_dst;             /*    4: IP destination */         \
  struct in_addr ip_dst_mask;                                           \

  /* filter end */

  struct filter {
    LIBMARC_FILTER_DEF
  };

  struct filter_packed {
    LIBMARC_FILTER_DEF
  }  __attribute__((packed));

  int filter_from_argv(int* argc, char** argv, struct filter*);
  void filter_from_argv_usage();

  /**
   * Convert string to destination.
   */
  int destination_aton(destination_t* dst, const char* src, enum DestinationType type);

  /**
   * Convert destination to string. The string is returned in a statically
   * allocated buffer, which subsequent calls will overwrite.
   */
  const char* destination_ntoa(const destination_t* src);

  /**
   * Like destination_ntoa but writes into buf.
   */
  const char* destination_ntoa_r(const destination_t* src, char buf[22]);

  /**
   * Display a representation of the filter.
   */
  void filter_print(const struct filter* filter, FILE* fp, int verbose);

  /**
   * Try to match a packet against the filter.
   * @param pkt Pointer to beginning of packet.
   * @param head Capture header.
   * @return Return non-zero if packet matches.
   */
  int filter_match(const struct filter* filter, const void* pkt, struct cap_header* head);

  int filter_close(struct filter* filter);

#ifdef __cplusplus
}
#endif

#endif /* CAPUTILS_FILTER_H */
