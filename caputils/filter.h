#ifndef CAPUTILS_FILTER_H
#define CAPUTILS_FILTER_H

#include <caputils/capture.h>
#include <caputils/picotime.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif

  typedef char CI_handle_t[8];

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
  unsigned char destaddr[22];        /* Destination Address. */		\
  uint32_t destport;                 /* Destination Port, used for udp and tcp sockets. */ \
  uint32_t type;                     /* Consumer Stream Type; 0-file, 1-ethernet multicast, 2-udp, 3-tcp */ \
                                                                        \
  /* filter 0.7 extensions */                                           \
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
