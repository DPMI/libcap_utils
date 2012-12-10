#ifndef CAPUTILS_FILTER_H
#define CAPUTILS_FILTER_H

#include <caputils/address.h>
#include <caputils/capture.h>
#include <caputils/picotime.h>

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/**
 * Filter versions
 *
 * Version 0 (legacy filter) sends lots of fields as ASCII (e.g. ip-adresses)
 * Version 1 deprecates ASCII fields and adds integer fields but still has old fields (but unset during transit)
 * Version 2 adds mode flag which toggles between AND and OR.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef char CI_handle_t[8];

enum FilterOffset {
	OFFSET_DST_PORT = 0,
	OFFSET_SRC_PORT,
	OFFSET_IP_DST,
	OFFSET_IP_SRC,
	OFFSET_IP_PROTO,
	OFFSET_ETH_DST,
	OFFSET_ETH_SRC,
	OFFSET_ETH_TYPE,
	OFFSET_VLAN,
	OFFSET_IFACE,
	OFFSET_MAMPID,
	OFFSET_END_TIME,
	OFFSET_START_TIME,
	OFFSET_PORT,

	/* Local filters (these is not used by MArCd, can be reordered) */
	OFFSET_FRAME_MAX_DT,
};

enum FilterBitmask {
	/* original */
	FILTER_DST_PORT = (1<<OFFSET_DST_PORT),
	FILTER_SRC_PORT = (1<<OFFSET_SRC_PORT),
	FILTER_IP_DST   = (1<<OFFSET_IP_DST),
	FILTER_IP_SRC   = (1<<OFFSET_IP_SRC),
	FILTER_IP_PROTO = (1<<OFFSET_IP_PROTO),
	FILTER_ETH_DST  = (1<<OFFSET_ETH_DST),
	FILTER_ETH_SRC  = (1<<OFFSET_ETH_SRC),
	FILTER_ETH_TYPE = (1<<OFFSET_ETH_TYPE),
	FILTER_VLAN     = (1<<OFFSET_VLAN),
	FILTER_IFACE    = (1<<OFFSET_IFACE),
	FILTER_CI       = (1<<OFFSET_IFACE), /* alias for FILTER_IFACE */

	/* filter 0.7 extensions */
	FILTER_MAMPID   = (1<<OFFSET_MAMPID),
	FILTER_END_TIME = (1<<OFFSET_END_TIME),
	FILTER_START_TIME=(1<<OFFSET_START_TIME),
	FILTER_PORT     = (1<<OFFSET_PORT), /* either src or dst port */

	/* local filters */
	FILTER_FRAME_MAX_DT = (1<<OFFSET_FRAME_MAX_DT),
};

enum FilterMode {
	FILTER_UNKNOWN = 0,
	FILTER_AND,
	FILTER_OR,
};

/**
 * This is the structure as represented internally within the host.
 */
struct filter {
	/* Integer identifying the rule. This should be uniqe for the MP. */
	uint32_t filter_id;
	uint32_t version;                  /* filter version */
	enum FilterMode mode;

	/* Which fields should we check? Bitmask (see further fields for values) */
	uint32_t index;

	/* filter 0.7 extensions */
	timepico starttime;                /* 4096: Time of first packet. */
	timepico endtime;                  /* 2048: Time of last packet. */
	char mampid[8];                    /* 1024: Match MAMPid */

	/* original fields */
	CI_handle_t iface;                 /* 512: Which CI */
	uint16_t vlan_tci;                 /* 256: VLAN id */
	uint16_t vlan_tci_mask;
	uint16_t eth_type;                 /* 128: Ethernet type */
	uint16_t eth_type_mask;
	struct ether_addr eth_src;         /*  64: Ethernet Source */
	struct ether_addr eth_src_mask;
	struct ether_addr eth_dst;         /*  32: Ethernet Destination */
	struct ether_addr eth_dst_mask;
	uint8_t ip_proto;                  /*  16: IP Payload Protocol */
	struct in_addr ip_src;             /*   8: IP source */
	struct in_addr ip_src_mask;
	struct in_addr ip_dst;             /*   4: IP destination */
	struct in_addr ip_dst_mask;
	uint16_t src_port;                 /*   2: Transport Source Port */
	uint16_t src_port_mask;
	uint16_t dst_port;                 /*   1: Transport Destination Port */
	uint16_t dst_port_mask;
	uint16_t port;                     /* 8192: src or dst port */
	uint16_t port_mask;

	/* local filters */
	timepico frame_max_dt;             /* reject all packets after a interarrival-time is higher than specified, no more packets will be matched */

	/* BFP filter (if supported) */
	struct bpf_insn* bpf_insn;
	char* bpf_expr;

	/* state */
	int first;                         /* 1 if this is the first packet */
	timepico frame_last_ts;            /* timestamp of the previous packet */

	/* destination */
	uint32_t consumer;                 /* Destination Consumer */
	uint32_t caplen;                   /* Amount of data to capture. */
	stream_addr_t dest;                /* Destination. */
};

/**
 * This is whats transmitted across the network.
 **/
struct filter_packed {
	/* Integer identifying the rule. This should be uniqe for the MP. */
	uint32_t filter_id;

	/* Which fields should we check? Bitmask (see further fields for values) */
	uint32_t index;
	CI_handle_t iface;                 /* 512: Which CI */
	uint16_t vlan_tci;                 /* 256: VLAN id */
	uint16_t eth_type;                 /* 128: Ethernet type */
	struct ether_addr eth_src;         /*  64: Ethernet Source */
	struct ether_addr eth_dst;         /*  32: Ethernet Destination */
	uint8_t ip_proto;                  /*  16: IP Payload Protocol */
	unsigned char _ip_src[16];          /*   8: IP source */
	unsigned char _ip_dst[16];          /*   4: IP destination */
	uint16_t src_port;                 /*   2: Transport Source Port */
	uint16_t dst_port;                 /*   1: Transport Destination Port */

	uint16_t vlan_tci_mask;            /* VLAN id mask */
	uint16_t eth_type_mask;            /* Ethernet type mask */
	struct ether_addr eth_src_mask;    /* Ethernet Source Mask */
	struct ether_addr eth_dst_mask;    /* Ethernet Destination Mask */
	unsigned char _ip_src_mask[16];    /* DO NOT USE. FOR COMPAT ONLY */
	unsigned char _ip_dst_mask[16];    /* DO NOT USE. FOR COMPAT ONLY */
	uint16_t src_port_mask;            /* Transport Source Port Mask */
	uint16_t dst_port_mask;            /* Transport Destination Port Mask */
	uint32_t consumer;                 /* Destination Consumer */
	uint32_t caplen;                   /* Amount of data to capture. */

	stream_addr_t dest;                /* Destination. */

	/* filter 0.7 extensions */
	uint32_t version;                  /* filter version */
	timepico starttime;                /* 4096: Time of first packet. */
	timepico endtime;                  /* 2048: Time of last packet. */
	char mampid[8];                    /* 1024: Match MAMPid */
	struct in_addr ip_src;             /*    8: IP source */
	struct in_addr ip_src_mask;
	struct in_addr ip_dst;             /*    4: IP destination */
	struct in_addr ip_dst_mask;
	uint16_t port;                     /* 8192: src or dst port */
	uint16_t port_mask;
	uint8_t mode;
} __attribute__((packed));

int filter_from_argv(int* argc, char** argv, struct filter*);
void filter_from_argv_usage(void);

void filter_src_port_set(struct filter* filter, uint16_t port, uint16_t mask);
void filter_dst_port_set(struct filter* filter, uint16_t port, uint16_t mask);

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
int filter_match(struct filter* filter, const void* pkt, struct cap_header* head);

int filter_close(struct filter* filter);

void filter_pack(struct filter* src, struct filter_packed* dst);
void filter_unpack(struct filter_packed* src, struct filter* dst);

#ifdef __cplusplus
}
#endif

#endif /* LIBMARC_FILTER_H */
