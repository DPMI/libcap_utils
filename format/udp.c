#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "format.h"

#define PORT_DNS 53

void print_udp(FILE* fp, const struct cap_header* cp, net_t net, const struct udphdr* udp, unsigned int flags){
	fputs("UDP", fp);

	const size_t header_size = sizeof(struct udphdr);
	const size_t total_size = ntohs(udp->len);
	const size_t payload_size = total_size - header_size;
	if ( flags & FORMAT_HEADER ){
		fprintf(fp, "(HDR[%zd]DATA[%zd])", header_size, payload_size);
	}

	const uint16_t sport = ntohs(udp->source);
	const uint16_t dport = ntohs(udp->dest);

	fprintf(fp, ": %s:%d --> %s:%d",
	        net->net_src, sport,
	        net->net_dst, dport);

	const char* payload = (const char*)udp + header_size;
	if ( sport == PORT_DNS || dport == PORT_DNS ){
		print_dns(fp, cp, payload, payload_size, flags);
	}
}
