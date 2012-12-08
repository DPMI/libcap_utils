#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "caputils/log.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>

static int is_ipv6_ext(uint8_t nxt){
	switch (nxt){
	case IPPROTO_HOPOPTS:
		return 1;
	default:
		return 0;
	}
}

static size_t ipv6_total_header_size(const struct ip6_hdr* ip, const char** ptr, uint8_t* proto){
	size_t header_size = sizeof(struct ip6_hdr);
	if ( !is_ipv6_ext(ip->ip6_nxt) ){
		*ptr = (const char*)ip + header_size;
		*proto = ip->ip6_nxt;
		return header_size;
	}

	const char* payload = (const char*)ip + header_size;
	const struct ip6_ext* ext = NULL;
	do {
		ext = (const struct ip6_ext*)payload;
		const size_t cur_size = ntohs(ext->ip6e_len) * 8 + 8;
		header_size += cur_size;
		payload += cur_size;
	} while ( is_ipv6_ext(ext->ip6e_nxt) );

	*ptr = payload;
	*proto = ext->ip6e_nxt;
	return header_size;
}

void print_ipv6(FILE* fp, const struct ip6_hdr* ip, unsigned int flags){
	const char* payload;
	uint8_t proto;
	const size_t header_size = ipv6_total_header_size(ip, &payload, &proto);

	if ( flags & FORMAT_HEADER ){
		fprintf(fp, "(HDR[%zd])[plen=%d,hops=%d]",
		        header_size, ntohs(ip->ip6_plen), ip->ip6_hops);
	}
	fputs(": ", fp);

	switch ( proto ){
	case IPPROTO_UDP:
		fprintf(fp, "UDP");
		break;

	case IPPROTO_ICMPV6:
		fprintf(fp, "ICMPv6");
		break;

	default:
		fprintf(fp, "unknown transport %d", proto);
	}

	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];

	fprintf(fp, " %s --> %s",
	        inet_ntop(AF_INET6, &ip->ip6_src, src, INET6_ADDRSTRLEN),
	        inet_ntop(AF_INET6, &ip->ip6_dst, dst, INET6_ADDRSTRLEN));
}
