#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "format.h"
#include <caputils/utils.h>
#include <string.h>

void print_arp(FILE* dst, const struct cap_header* cp, const struct ether_arp* arp){
	fprintf(dst, " ARP: ");

	const int format = ntohs(arp->arp_hrd);
	const int op = ntohs(arp->arp_op);

	if ( format == ARPHRD_ETHER ){
		union {
			uint8_t v[4];
			struct in_addr addr;
		} spa, tpa;
		memcpy(spa.v, arp->arp_spa, 4);
		memcpy(tpa.v, arp->arp_tpa, 4);

		switch ( op ){
		case ARPOP_REQUEST:
			fputs("Request who-has ", dst);
			fputs(inet_ntoa(tpa.addr), dst);
			fputs(" tell ", dst);
			fputs(inet_ntoa(spa.addr), dst);
			break;

		case ARPOP_REPLY:
			fputs("Reply ", dst);
			fputs(inet_ntoa(spa.addr), dst);
			fputs(" is-at ", dst);
			fputs(hexdump_address((const struct ether_addr*)arp->arp_sha), dst);
			break;

		case ARPOP_RREQUEST:
			fputs("RARP request", dst);
			break;

		case ARPOP_RREPLY:
			fputs("RARP reply", dst);
			break;

		default:
			fprintf(dst, "Unknown op: %d", op);
		}
	} else {
		fprintf(dst, "Unknown format: %d", format);
	}

	fprintf(dst, ", length %zd", cp->len - sizeof(struct ethhdr));
}
