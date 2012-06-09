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

static void print_tcp(FILE* dst, const struct ip* ip, const struct tcphdr* tcp){
	fprintf(dst, "TCP(HDR[%d]DATA[%0x]):\t [",4*tcp->doff, ntohs(ip->ip_len) - 4*tcp->doff - 4*ip->ip_hl);
	if(tcp->syn) {
		fprintf(dst, "S");
	}
	if(tcp->fin) {
		fprintf(dst, "F");
	}
	if(tcp->ack) {
		fprintf(dst, "A");
	}
	if(tcp->psh) {
		fprintf(dst, "P");
	}
	if(tcp->urg) {
		fprintf(dst, "U");
	}
	if(tcp->rst) {
		fprintf(dst, "R");
	}

	fprintf(dst, "] %s:%d ",inet_ntoa(ip->ip_src),(u_int16_t)ntohs(tcp->source));
	fprintf(dst, " --> %s:%d",inet_ntoa(ip->ip_dst),(u_int16_t)ntohs(tcp->dest));
	fprintf(dst, "\n");
}

static void print_udp(FILE* dst, const struct ip* ip, const struct udphdr* udp){
	fprintf(dst, "UDP(HDR[8]DATA[%d]):\t %s:%d ",(u_int16_t)(ntohs(udp->len)-8),inet_ntoa(ip->ip_src),(u_int16_t)ntohs(udp->source));
	fprintf(dst, " --> %s:%d", inet_ntoa(ip->ip_dst),(u_int16_t)ntohs(udp->dest));
	fprintf(dst, "\n");
}

static void print_icmp(FILE* dst, const struct ip* ip, const struct icmphdr* icmp){
	fprintf(dst, "ICMP:\t %s ",inet_ntoa(ip->ip_src));
	fprintf(dst, " --> %s ",inet_ntoa(ip->ip_dst));
	fprintf(dst, "Type %d , code %d", icmp->type, icmp->code);
	if( icmp->type==0 && icmp->code==0){
		fprintf(dst, " echo reply: SEQNR = %d ", icmp->un.echo.sequence);
	}
	if( icmp->type==8 && icmp->code==0){
		fprintf(dst, " echo reqest: SEQNR = %d ", icmp->un.echo.sequence);
	}
	fprintf(dst, "\n");
}

static void print_ipv4(FILE* dst, const struct ip* ip){
	void* payload = ((char*)ip) + 4*ip->ip_hl;
	fprintf(dst, "IPv4(HDR[%d])[", 4*ip->ip_hl);
	fprintf(dst, "Len=%d:",(u_int16_t)ntohs(ip->ip_len));
	fprintf(dst, "ID=%d:",(u_int16_t)ntohs(ip->ip_id));
	fprintf(dst, "TTL=%d:",(u_int8_t)ip->ip_ttl);
	fprintf(dst, "Chk=%d:",(u_int16_t)ntohs(ip->ip_sum));

	if(ntohs(ip->ip_off) & IP_DF) {
		fprintf(dst, "DF");
	}
	if(ntohs(ip->ip_off) & IP_MF) {
		fprintf(dst, "MF");
	}

	fprintf(dst, " Tos:%0x]:\t",(u_int8_t)ip->ip_tos);

	switch( ip->ip_p ) {
	case IPPROTO_TCP:
		print_tcp(dst, ip, (const struct tcphdr*)payload);
		break;

	case IPPROTO_UDP:
		print_udp(dst, ip, (const struct udphdr*)payload);
		break;

	case IPPROTO_ICMP:
		print_icmp(dst, ip, (const struct icmphdr*)payload);
		break;

	case IPPROTO_IGMP:
		fprintf(dst, "IGMP");
		break;

	default:
		fprintf(dst, "Unknown transport protocol: %d \n", ip->ip_p);
		break;
	}
}

static void print_ieee8023(FILE* dst, const struct llc_pdu_sn* llc){
	fprintf(dst,"dsap=%02x ssap=%02x ctrl1 = %02x ctrl2 = %02x\n", llc->dsap, llc->ssap, llc->ctrl_1, llc->ctrl_2);
}

static void print_eth(FILE* dst, const struct ethhdr* eth){
	void* payload = ((char*)eth) + sizeof(struct ethhdr);
	uint16_t h_proto = ntohs(eth->h_proto);
	uint16_t vlan_tci;

 begin:

	if(h_proto<0x05DC){
		fprintf(dst, "IEEE802.3 ");
		fprintf(dst, "  %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x ",
		        eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5],
		        eth->h_dest[0],  eth->h_dest[1],  eth->h_dest[2],  eth->h_dest[3],  eth->h_dest[4],  eth->h_dest[5]);
		print_ieee8023(dst,(struct llc_pdu_sn*)payload);
	} else {
		switch ( h_proto ){
		case ETHERTYPE_VLAN:
			vlan_tci = ((uint16_t*)payload)[0];
			h_proto = ntohs(((uint16_t*)payload)[0]);
			payload = ((char*)eth) + sizeof(struct ethhdr);
			fprintf(dst, "802.1Q vlan# %d: ", 0x0FFF&ntohs(vlan_tci));
			goto begin;

		case ETHERTYPE_IP:
			print_ipv4(dst, (struct ip*)payload);
			break;

		case ETHERTYPE_IPV6:
			printf("ipv6\n");
			break;

		case ETHERTYPE_ARP:
			printf("arp\n");
			break;

		case 0x0810:
			fprintf(dst, "MP packet\n");
			break;

		case STPBRIDGES:
			fprintf(dst, "STP(0x%04x): (spanning-tree for bridges)\n", h_proto);
			break;

		case CDPVTP:
			fprintf(dst, "CDP(0x%04x): (CISCO Discovery Protocol)\n", h_proto);
			break;

		default:
			fprintf(dst, "Unknown ethernet protocol (0x%04x),  ", h_proto);
			fprintf(dst, " %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x \n",
			        eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5],
			        eth->h_dest[0],  eth->h_dest[1],  eth->h_dest[2],  eth->h_dest[3],  eth->h_dest[4],  eth->h_dest[5]);
			break;
		}
	}
}

static void print_timestamp(FILE* fp, const struct cap_header* cp, int flags){
	const int format_date  = flags & FORMAT_DATE_BIT;
	const int format_local = flags & FORMAT_LOCAL_BIT;
	const int relative     = flags & FORMAT_REL_TIMESTAMP;

	if( !format_date ) {
		timepico t = cp->ts;
		if ( relative ){
			static timepico ref;;
			static int first = 1;
			if ( first ){
				ref = t;
				first = 0;
			}
			t = timepico_sub(t, ref);
		}
		fprintf(fp, "%u.%012"PRIu64, t.tv_sec, t.tv_psec);
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

static void print_linklayer(FILE* fp, const struct cap_header* cp, int flags){
	fprintf(fp, ":LINK(%4d):CAPLEN(%4d):", cp->len, cp->caplen);

	/* Test for libcap_utils marker packet */
	struct marker mark;
	int marker_port;
	if ( (marker_port=is_marker(cp, &mark, 0)) != 0 ){
		fprintf(stdout, "Marker [e=%d, r=%d, k=%d, s=%d, port=%d]\n",
		        mark.exp_id, mark.run_id, mark.key_id, mark.seq_num, marker_port);
		return;
	}

	print_eth(fp, cp->ethhdr);
}

void format_pkg(FILE* fp, const stream_t st, const struct cap_header* cp, int flags){
	fprintf(fp, "[%4"PRIu64"]:%.4s:%.8s:", st->stat.read, cp->nic, cp->mampid);

	print_timestamp(fp, cp, flags);
	print_linklayer(fp, cp, flags);
}
