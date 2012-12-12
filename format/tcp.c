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

	if ( flags & FORMAT_HEADER ){
		fprintf(fp, "(HDR[%d]DATA[%0zx])", 4*tcp->doff, net->plen - 4*tcp->doff);
	}

	fprintf(fp, ": [%s] %s:%d --> %s:%d", tcp_flags(tcp),
	        net->net_src, ntohs(tcp->source),
	        net->net_dst, ntohs(tcp->dest));
}
