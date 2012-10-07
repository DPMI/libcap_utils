#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "caputils/marker.h"
#include "caputils_int.h"
#include <netinet/udp.h>

#ifndef HAVE_BE64TOH
#include "be64toh.h"
#endif

int is_marker(const struct cap_header* cp, struct marker* ptr, int port){
	/* match ip packet */
	const struct ip* ip = find_ip_header(cp->ethhdr);
	if ( !ip ){ return 0; }

	/* match udp packet */
	uint16_t src, dst;
	const struct udphdr* udp = find_udp_header(cp->payload, cp->ethhdr, ip, &src, &dst);
	if ( !(udp && src == MARKERPORT && (dst == port || port == 0)) ){ return 0; }

	/* match magic */
	const struct marker* marker = (const struct marker*)((const char*)udp + sizeof(struct udphdr));
	if ( ntohl(marker->magic) != MARKER_MAGIC ){ return 0; }

	/* assume it is a marker */
	if ( ptr ){
		ptr->magic = ntohl(marker->magic);
		ptr->version = marker->version;
		ptr->flags = marker->flags;
		ptr->reserved = ntohs(marker->reserved);
		ptr->exp_id = ntohl(marker->exp_id);
		ptr->run_id = ntohl(marker->run_id);
		ptr->key_id = ntohl(marker->key_id);
		ptr->seq_num = ntohl(marker->seq_num);
		ptr->timestamp = be64toh(marker->timestamp);
	}

	return dst;
}
