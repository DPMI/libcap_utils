#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "caputils/stream.h"
#include "caputils/filter.h"
#include "caputils/utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>

#ifndef ETHERTYPE_IPV6 /* libc might not provide this if it is missing ipv6 support */
#define ETHERTYPE_IPV6 0x86dd
#endif /* ETHERTYPE_IPV6 */

#define STPBRIDGES 0x0026
#define CDPVTP 0x016E

struct llc_pdu_sn {
  uint8_t dsap;
  uint8_t ssap;
  uint8_t ctrl_1;
  uint8_t ctrl_2;
};

static int keep_running = 1;
static int print_content = 0;
static int print_date = 0;
static int max_packets = 0;
static const char* iface = NULL;
static struct timeval timeout = {1,0};
static const char* program_name = NULL;

void handle_sigint(int signum){
	if ( keep_running == 0 ){
		fprintf(stderr, "\rGot SIGINT again, terminating.\n");
		abort();
	}
	fprintf(stderr, "\rAborting capture.\n");
	keep_running = 0;
}

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

static struct option long_options[]= {
	{"content",  no_argument,       0, 'c'},
	{"packets",  required_argument, 0, 'p'},
	{"iface",    required_argument, 0, 'i'},
	{"timeout",  required_argument, 0, 't'},
	{"calender", no_argument,       0, 'd'},
	{"help",     no_argument,       0, 'h'},
	{0, 0, 0, 0} /* sentinel */
};

static void show_usage(void){
	printf("consumer-ls-" VERSION "\n");
	printf("(C) 2004 Patrik Arlos <patrik.arlos@bth.se>\n");
	printf("(C) 2012 David Sveningsson <david.sveningsson@bth.se>\n");
	printf("Usage: %s [OPTIONS] STREAM\n", program_name);
	printf("  -c, --content        Write full package content as hexdump. [default=no]\n"
	       "  -i, --iface          For ethernet-based streams, this is the interface to listen\n"
	       "                       on. For other streams it is ignored.\n"
	       "  -p, --packets=N      Stop after N packets.\n"
	       "  -t, --timeout=N      Wait for N ms while buffer fills [default: 1000ms].\n"
	       "  -d, --calender       Show timestamps in human-readable format.\n"
	       "  -h, --help           This text.\n\n");
	filter_from_argv_usage();
}

int main(int argc, char **argv){
  /* extract program name from path. e.g. /path/to/MArCd -> MArCd */
  const char* separator = strrchr(argv[0], '/');
  if ( separator ){
    program_name = separator + 1;
  } else {
    program_name = argv[0];
  }

	struct filter filter;
	if ( filter_from_argv(&argc, argv, &filter) != 0 ){
		return 0; /* error already shown */
	}

	filter_print(&filter, stderr, 1);

	int op, option_index = -1;
	while ( (op = getopt_long(argc, argv, "hcdi:p:t:", long_options, &option_index)) != -1 ){
		switch (op){
		case 0:   /* long opt */
		case '?': /* unknown opt */
			break;

		case 'd':
			print_date = 1;
			break;

		case 'p':
			max_packets = atoi(optarg);
			break;

		case 't':
			{
				int tmp = atoi(optarg);
				timeout.tv_sec  = tmp / 1000;
				timeout.tv_usec = tmp % 1000 * 1000;
			}
			break;

		case 'c':
			print_content = 1;
			break;

		case 'i':
			iface = optarg;
			break;

		case 'h':
			show_usage();
			return 0;

		default:
			printf ("?? getopt returned character code 0%o ??\n", op);
		}
	}

	int ret;

	/* Open stream(s) */
	struct stream* stream;
	if ( (ret=stream_from_getopt(&stream, argv, optind, argc, iface, program_name)) != 0 ) {
		return ret; /* Error already shown */
	}
	const stream_stat_t* stat = stream_get_stat(stream);
	stream_print_info(stream, stderr);

	/* handle C-c */
	signal(SIGINT, handle_sigint);

	while ( keep_running ) {
		/* A short timeout is used to allow the application to "breathe", i.e
		 * terminate if SIGINT was received. */
		struct timeval tv = timeout;

		/* Read the next packet */
		cap_head* cp;
		ret = stream_read(stream, &cp, &filter, &tv);
		if ( ret == EAGAIN ){
			continue; /* timeout */
		} else if ( ret != 0 ){
			break; /* shutdown or error */
		}

		time_t time = (time_t)cp->ts.tv_sec;
		fprintf(stdout, "[%4"PRIu64"]:%.4s:%.8s:", stat->matched, cp->nic, cp->mampid);
		if( print_date == 0 ) {
			fprintf(stdout, "%u.", cp->ts.tv_sec);
		} else {
			static char timeStr[25];
			struct tm tm = *gmtime(&time);
			strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &tm);
			fprintf(stdout, "%s.", timeStr);
		}

		fprintf(stdout, "%012"PRId64":LINK(%4d):CAPLEN(%4d):", cp->ts.tv_psec, cp->len, cp->caplen);
		print_eth(stdout, (struct ethhdr*)cp->payload);

		if ( max_packets > 0 && stat->matched >= max_packets) {
			/* Read enough pkts lets break. */
			printf("read enought packages\n");
			break;
		}
	}

	/* if ret == -1 the stream was closed properly (e.g EOF or TCP shutdown)
	 * In addition EINTR should not give any errors because it is implied when the
	 * user presses C-c */
	if ( ret > 0 && ret != EINTR ){
		fprintf(stderr, "stream_read() returned 0x%08X: %s\n", ret, caputils_error_string(ret));
	}

	/* Release resources */
	stream_close(stream);
	filter_close(&filter);

	/* Write stats */
	fprintf(stderr, "%"PRIu64" packets received.\n", stat->read);
	fprintf(stderr, "%"PRIu64" packets matched filter.\n", stat->matched);
	return 0;
}
