#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "format.h"

void print_ipv4(FILE* fp, const struct ip* ip, unsigned int flags){
	const void* payload = ((const char*)ip) + 4*ip->ip_hl;

	if ( flags & FORMAT_HEADER ){
		fprintf(fp, "(HDR[%d])[", 4*ip->ip_hl);
		fprintf(fp, "Len=%d:",(u_int16_t)ntohs(ip->ip_len));
		fprintf(fp, "ID=%d:",(u_int16_t)ntohs(ip->ip_id));
		fprintf(fp, "TTL=%d:",(u_int8_t)ip->ip_ttl);
		fprintf(fp, "Chk=%d:",(u_int16_t)ntohs(ip->ip_sum));
		if ( ntohs(ip->ip_off) & IP_DF) fprintf(fp, "DF");
		if ( ntohs(ip->ip_off) & IP_MF) fprintf(fp, "MF");
		fprintf(fp, " Tos:%0x]",(u_int8_t)ip->ip_tos);
	}
	fputs(": ", fp);

	char src[INET_ADDRSTRLEN];
	char dst[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &ip->ip_src, src, sizeof(src));
	inet_ntop(AF_INET, &ip->ip_dst, dst, sizeof(dst));

	struct network net = {
		.net_src = src,
		.net_dst = dst,
		.plen = ntohs(ip->ip_len) - 4*ip->ip_hl,
	};
	print_ipproto(fp, &net, ip->ip_p, payload, flags);
}
