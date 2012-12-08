#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>

void print_ipv6(FILE* fp, const struct ip6_hdr* ip, unsigned int flags){
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];

	fprintf(fp, ": %s --> %s",
	        inet_ntop(AF_INET6, &ip->ip6_src, src, INET6_ADDRSTRLEN),
	        inet_ntop(AF_INET6, &ip->ip6_dst, dst, INET6_ADDRSTRLEN));
}
