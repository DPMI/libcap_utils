#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "format.h"
#include "caputils/caputils.h"
#include "caputils/log.h"
#include <stdio.h>
#include <arpa/inet.h>

void print_ipproto(FILE* fp, net_t net, uint8_t proto, const char* payload, unsigned int flags){
	switch( proto ) {
	case IPPROTO_TCP:
		print_tcp(fp, net, (const struct tcphdr*)payload, flags);
		break;

	case IPPROTO_UDP:
		print_udp(fp, net, (const struct udphdr*)payload, flags);
		break;

	case IPPROTO_ICMP:
		print_icmp(fp, net, (const struct icmphdr*)payload, flags);
		break;

	case IPPROTO_ICMPV6:
		fprintf(fp, "ICMPv6");
		break;

	case IPPROTO_IGMP:
		fprintf(fp, "IGMP");
		break;

	case IPPROTO_OSPF:
		fprintf(fp, "OSPF");
		break;

	default:
		fprintf(fp, "Unknown transport protocol: %d", proto);
		break;
	}
}
