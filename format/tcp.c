#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "format.h"

static const char* tcp_flags(const struct tcphdr* tcp){
	static char buf[12];
	size_t i = 0;

	if (tcp->syn) buf[i++] = 'S';
	if (tcp->fin) buf[i++] = 'F';
	if (tcp->ack) buf[i++] = 'A';
	if (tcp->psh) buf[i++] = 'P';
	if (tcp->urg) buf[i++] = 'U';
	if (tcp->rst) buf[i++] = 'R';
	buf[i++] = 0;

	return buf;
}

void print_tcp(FILE* fp, const struct cap_header* cp, net_t net, const struct tcphdr* tcp, unsigned int flags){
	fputs("TCP", fp);

	const size_t header_size = 4*tcp->doff;
	const size_t payload_size = net->plen - header_size;
	if ( flags & FORMAT_HEADER ){
		fprintf(fp, "(HDR[%zd]DATA[%zd])", header_size, payload_size);
	}

	const uint16_t sport = ntohs(tcp->source);
	const uint16_t dport = ntohs(tcp->dest);

	fprintf(fp, ": [%s] %s:%d --> %s:%d", tcp_flags(tcp),
	        net->net_src, sport,
	        net->net_dst, dport);

	const char* payload = (const char*)tcp + 4*tcp->doff;
	if ( payload_size > 0 && (sport == PORT_DNS || dport == PORT_DNS) ){
		/* offset the length field */
		print_dns(fp, cp, payload + 2, payload_size - 2, flags);
	}
}
