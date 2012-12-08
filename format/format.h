#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <caputils/log.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

struct network {
	const char* net_src; /* human-readable representation of src address */
	const char* net_dst; /* human-readable representation of dst address */
	size_t plen;         /* payload size (not including network headers) */
};
typedef const struct network* net_t;

/* layer 2 */
void print_eth(FILE* dst, const struct cap_header* cp, const struct ethhdr* eth, unsigned int flags);

/* layer 3 */
void print_ipproto(FILE* fp, net_t net, uint8_t proto, const char* payload, unsigned int flags);
void print_ipv4(FILE* fp, const struct ip* ip, unsigned int flags);
void print_ipv6(FILE* fp, const struct ip6_hdr* ip, unsigned int flags);
void print_arp(FILE* dst, const struct cap_header* cp, const struct ether_arp* arp);

/* layer 4 */
void print_tcp(FILE* fp, net_t net, const struct tcphdr* tcp, unsigned int flags);
void print_udp(FILE* fp, net_t net, const struct udphdr* udp, unsigned int flags);
void print_icmp(FILE* fp, net_t net, const struct icmphdr* icmp, unsigned int flags);
