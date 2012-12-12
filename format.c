#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "caputils/caputils.h"
#include "caputils/log.h"
#include "caputils/marker.h"
#include "caputils/stream.h"
#include "caputils/picotime.h"
#include "stream.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/time.h>

static int min(int a, int b){ return a<b?a:b; }

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

static void print_tcp(FILE* dst, const struct ip* ip, const struct tcphdr* tcp, unsigned int flags){
	fputs("TCP", dst);

	if ( flags & FORMAT_HEADER ){
		fprintf(dst, "(HDR[%d]DATA[%0x])",4*tcp->doff, ntohs(ip->ip_len) - 4*tcp->doff - 4*ip->ip_hl);
	}


	fprintf(dst, ": [%s] %s:%d", tcp_flags(tcp), inet_ntoa(ip->ip_src), (u_int16_t)ntohs(tcp->source));
	fprintf(dst, " --> %s:%d",inet_ntoa(ip->ip_dst),(u_int16_t)ntohs(tcp->dest));
}

static void print_udp(FILE* dst, const struct ip* ip, const struct udphdr* udp, unsigned int flags){
	fputs("UDP", dst);

	if ( flags & FORMAT_HEADER ){
		fprintf(dst, "(HDR[%zd]DATA[%zd])", sizeof(struct udphdr), ntohs(udp->len)-sizeof(struct udphdr));
	}

	const uint16_t sport = ntohs(udp->source);
	const uint16_t dport = ntohs(udp->dest);

	fprintf(dst, ": %s:%d",    inet_ntoa(ip->ip_src), sport);
	fprintf(dst, " --> %s:%d", inet_ntoa(ip->ip_dst), dport);
}

static void print_icmp(FILE* dst, const struct ip* ip, const struct icmphdr* icmp, unsigned int flags){
	fputs("ICMP", dst);
	if ( flags & FORMAT_HEADER ){
		fprintf(dst, "[Type=%d, code=%d]", icmp->type, icmp->code);
	}

	fprintf(dst, ": %s ",inet_ntoa(ip->ip_src));
	fprintf(dst, "--> %s",inet_ntoa(ip->ip_dst));

	if ( flags < (unsigned int)FORMAT_LAYER_APPLICATION ){
		return;
	}
	fputs(": ", dst);

	switch ( icmp->type ){
	case ICMP_ECHOREPLY:
		fprintf(dst, "echo reply: SEQNR = %d ", icmp->un.echo.sequence);
		break;

	case ICMP_DEST_UNREACH:
		switch ( icmp->code ){
		case ICMP_NET_UNREACH:    fprintf(dst, "Destination network unreachable"); break;
		case ICMP_HOST_UNREACH:   fprintf(dst, "Destination host unreachable"); break;
		case ICMP_PROT_UNREACH:   fprintf(dst, "Destination protocol unreachable"); break;
		case ICMP_PORT_UNREACH:   fprintf(dst, "Destination port unreachable"); break;
		case ICMP_FRAG_NEEDED:    fprintf(dst, "Fragmentation required"); break;
		case ICMP_SR_FAILED:      fprintf(dst, "Source route failed"); break;
		case ICMP_NET_UNKNOWN:    fprintf(dst, "Destination network unknown"); break;
		case ICMP_HOST_UNKNOWN:   fprintf(dst, "Destination host unknown"); break;
		case ICMP_HOST_ISOLATED:  fprintf(dst, "Source host isolated"); break;
		case ICMP_NET_ANO:        fprintf(dst, "Network administratively prohibited"); break;
		case ICMP_HOST_ANO:       fprintf(dst, "Host administratively prohibited"); break;
		case ICMP_NET_UNR_TOS:    fprintf(dst, "Network unreachable for TOS"); break;
		case ICMP_HOST_UNR_TOS:   fprintf(dst, "Host unreachable for TOS"); break;
		case ICMP_PKT_FILTERED:   fprintf(dst, "Communication administratively prohibited"); break;
		case ICMP_PREC_VIOLATION: fprintf(dst, "Host Precedence Violation"); break;
		case ICMP_PREC_CUTOFF:    fprintf(dst, "Precedence cutoff in effect"); break;
		default: fprintf(dst, "Destination unreachable (code %d)\n", icmp->code);
		}
		break;

	case ICMP_SOURCE_QUENCH:
		fprintf(dst, "source quench");
		break;

	case ICMP_REDIRECT:
		fprintf(dst, "redirect");
		break;

	case ICMP_ECHO:
		fprintf(dst, "echo reqest: SEQNR = %d ", icmp->un.echo.sequence);
		break;

	case ICMP_TIME_EXCEEDED:
		fprintf(dst, "time exceeded");
		break;

	case ICMP_TIMESTAMP:
		fprintf(dst, "timestamp request");
		break;

	case ICMP_TIMESTAMPREPLY:
		fprintf(dst, "timestamp reply");
		break;

	default:
		fprintf(dst, "Type %d\n", icmp->type);
	}
}

static void print_ipv4(FILE* dst, const struct ip* ip, unsigned int flags){
	const void* payload = ((const char*)ip) + 4*ip->ip_hl;

	if ( flags & FORMAT_HEADER ){
		fprintf(dst, "(HDR[%d])[", 4*ip->ip_hl);
		fprintf(dst, "Len=%d:",(u_int16_t)ntohs(ip->ip_len));
		fprintf(dst, "ID=%d:",(u_int16_t)ntohs(ip->ip_id));
		fprintf(dst, "TTL=%d:",(u_int8_t)ip->ip_ttl);
		fprintf(dst, "Chk=%d:",(u_int16_t)ntohs(ip->ip_sum));
		if ( ntohs(ip->ip_off) & IP_DF) fprintf(dst, "DF");
		if ( ntohs(ip->ip_off) & IP_MF) fprintf(dst, "MF");
		fprintf(dst, " Tos:%0x]",(u_int8_t)ip->ip_tos);
	}
	fputs(": ", dst);

	switch( ip->ip_p ) {
	case IPPROTO_TCP:
		print_tcp(dst, ip, (const struct tcphdr*)payload, flags);
		break;

	case IPPROTO_UDP:
		print_udp(dst, ip, (const struct udphdr*)payload, flags);
		break;

	case IPPROTO_ICMP:
		print_icmp(dst, ip, (const struct icmphdr*)payload, flags);
		break;

	case IPPROTO_IGMP:
		fprintf(dst, "IGMP");
		break;

	case IPPROTO_OSPF:
		fprintf(dst, "OSPF");
		break;

	default:
		fprintf(dst, "Unknown transport protocol: %d", ip->ip_p);
		break;
	}
}

static void print_ieee8023(FILE* dst, const struct llc_pdu_sn* llc){
	fprintf(dst,"dsap=%02x ssap=%02x ctrl1 = %02x ctrl2 = %02x", llc->dsap, llc->ssap, llc->ctrl_1, llc->ctrl_2);
}

static void print_arp(FILE* dst, const struct cap_header* cp, const struct ether_arp* arp){
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

static void print_eth(FILE* dst, const struct cap_header* cp, const struct ethhdr* eth, unsigned int flags){
	const void* payload = ((const char*)eth) + sizeof(struct ethhdr);
	uint16_t h_proto = ntohs(eth->h_proto);
	uint16_t vlan_tci;

 begin:

	switch ( h_proto ){
	case ETHERTYPE_VLAN:
		vlan_tci = ((const uint16_t*)payload)[0];
		h_proto = ntohs(((const uint16_t*)payload)[0]);
		payload = ((const char*)eth) + sizeof(struct ethhdr);
		fprintf(dst, "802.1Q vlan# %d: ", 0x0FFF&ntohs(vlan_tci));
		goto begin;

	case ETHERTYPE_IP:
		fputs(" IPv4", dst);
		if ( flags >= FORMAT_LAYER_TRANSPORT ){
			print_ipv4(dst, (const struct ip*)payload, flags);
		}
		break;

	case ETHERTYPE_IPV6:
		fputs(" IPv6", dst);
		break;

	case ETHERTYPE_ARP:
		print_arp(dst, cp, (const struct ether_arp*)payload);
		break;

	case 0x0810:
		fprintf(dst, " MP packet");
		break;

	case STPBRIDGES:
		fprintf(dst, " STP(0x%04x): (spanning-tree for bridges)", h_proto);
		break;

	case CDPVTP:
		fprintf(dst, " CDP(0x%04x): (CISCO Discovery Protocol)", h_proto);
		break;

	default:
		fprintf(dst, " IEEE802.3 [0x%04x] ", h_proto);
		fputs(hexdump_address((const struct ether_addr*)eth->h_source), dst);
		fputs(" -> ", dst);
		fputs(hexdump_address((const struct ether_addr*)eth->h_dest), dst);
		if(h_proto<0x05DC){
			fputs(" ", dst);
			print_ieee8023(dst, (const struct llc_pdu_sn*)payload);
		}
		break;
	}
}

static void print_timestamp(FILE* fp, struct format* state, const struct cap_header* cp){
	const int format_date  = state->flags & FORMAT_DATE_BIT;
	const int format_local = state->flags & FORMAT_LOCAL_BIT;
	const int relative     = state->flags & FORMAT_REL_TIMESTAMP;

	if( !format_date ) {
		timepico t = cp->ts;
		int sign = 0; /* quick-and-dirty solution */

		if ( relative ){
			/* need to test if timestamp is less than reference in case multiple
			 * locations is present in trace in which case dt may be negative. */
			if ( timecmp(&t, &state->ref) >= 0 ){
				t = timepico_sub(t, state->ref);
				sign = 0;
			} else {
				t = timepico_sub(state->ref, t);
				sign = 1;
			}
		}

		fprintf(fp, "%s%u.%012"PRIu64, sign ? "-" : "", t.tv_sec, t.tv_psec);
		return;
	}

	static char buffer[32];
	time_t time = (time_t)cp->ts.tv_sec;
	struct tm* tm = format_local ? localtime(&time) : gmtime(&time);
	strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm);
	fprintf(fp, "%s.%012"PRIu64, buffer, cp->ts.tv_psec);
	strftime(buffer, sizeof(buffer), "%z", tm);
	fprintf(fp, " %s", buffer);
}

static void print_linklayer(FILE* fp, const struct cap_header* cp, unsigned int flags){
	fputc(':', fp);

	/* Test for libcap_utils marker packet */
	struct marker mark;
	int marker_port;
	if ( (marker_port=is_marker(cp, &mark, 0)) != 0 ){
		fprintf(stdout, "Marker [e=%d, r=%d, k=%d, s=%d, port=%d]",
		        mark.exp_id, mark.run_id, mark.key_id, mark.seq_num, marker_port);
		return;
	}

	print_eth(fp, cp, cp->ethhdr, flags);
}

static void print_pkt(FILE* fp, struct format* state, const struct cap_header* cp){
	print_timestamp(fp, state, cp);
	fprintf(fp, ":LINK(%4d):CAPLEN(%4d)", cp->len, cp->caplen);

	if ( state->flags >= FORMAT_LAYER_LINK ){
		print_linklayer(fp, cp, state->flags);
	}
	fputc('\n', fp);

	if ( state->flags & FORMAT_HEXDUMP ){
		hexdump(fp, cp->payload, min(cp->caplen, cp->len));
	}
}

void format_setup(struct format* state, unsigned int flags){
	state->pktcount = 0;
	state->first = 1;
	state->flags = flags;

	/* by default show all */
	if ( state->flags >> FORMAT_LAYER_BIT == 0){
		state->flags |= FORMAT_LAYER_APPLICATION;
	}
}

void format_pkg(FILE* fp, struct format* state, const struct cap_header* cp){
	fprintf(fp, "[%4"PRIu64"]:%.4s:%.8s:", state->pktcount++, cp->nic, cp->mampid);
	if ( state->first ){
		state->ref = cp->ts;
		state->first = 0;
	}
	print_pkt(fp, state, cp);
}

void format_ignore(FILE* fp, struct format* state, const struct cap_header* cp){
	state->pktcount++;
	if ( state->first ){
		state->ref = cp->ts;
		state->first = 0;
	}
}
