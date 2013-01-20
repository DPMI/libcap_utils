#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "format.h"

void print_udp(FILE* fp, net_t net, const struct udphdr* udp, unsigned int flags){
	fputs("UDP", fp);

	if ( flags & FORMAT_HEADER ){
		fprintf(fp, "(HDR[%zd]DATA[%zd])", sizeof(struct udphdr), ntohs(udp->len)-sizeof(struct udphdr));
	}

	fprintf(fp, ": %s:%d --> %s:%d",
	        net->net_src, ntohs(udp->source),
	        net->net_dst, ntohs(udp->dest));
}
