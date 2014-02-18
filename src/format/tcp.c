/**
 * libcap_utils - DPMI capture utilities
 * Copyright (C) 2003-2013 (see AUTHORS)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "format.h"

enum OptionKind {
	EOL = 0,
	NOP = 1,
	MSS = 2,
	WSOPT = 3,
	SACK_PERMITTED = 4,
	SACK = 5,
	TSOPT = 8,
};

typedef struct {
	u_int8_t kind;
	u_int8_t size;
} tcp_option_t;

typedef struct {
	u_int8_t kind;
	u_int8_t size;
	u_int16_t mss;
} tcpopt_mss_t;

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

static void tcp_options(const struct tcphdr* tcp, FILE* dst){
	if ( tcp->doff <= 5 ) return; /* no options present */

	fprintf(dst,"|");
	const uint8_t* ptr = (const u_int8_t*)((const char*)tcp) + sizeof(struct tcphdr);

	int optlen = sizeof(struct tcphdr);
	while ( *ptr != 0 && optlen < 4*tcp->doff ){
		const tcp_option_t* opt = (const tcp_option_t*)ptr;

		if ( opt->size == 0 ){
			fprintf(dst, "invalid flag size 0, aborting\n");
			break;
		}

		switch ( opt->kind ){
		case EOL:
			fprintf(dst, "EOL|");
			return;

		case NOP:
			fprintf(dst, "NOP|");
			ptr += 1;
			optlen += 1;
			continue;

		case MSS:
		{
			const tcpopt_mss_t* mss = (const tcpopt_mss_t*)ptr;
			fprintf(dst, "MSS(%d)|", ntohs(mss->mss));
			break;
		}

		case WSOPT: /* Windowscale factor */
		{
			uint8_t wf = *(ptr+sizeof(tcp_option_t));
			fprintf(dst, "WS(%d)|", wf);
			break;
		}

		case SACK_PERMITTED:
		case SACK:
			fprintf(dst, "SAC|");
			break;

		case TSOPT:
			fprintf(dst, "TSS|");
			break;

		default:
			fprintf(dst, "%d|", opt->kind);
			break;
		}

		ptr += opt->size;
		optlen += opt->size;
	}
}

void print_tcp(FILE* fp, const struct cap_header* cp, net_t net, const struct tcphdr* tcp, unsigned int flags){
	fputs("TCP", fp);
	if ( limited_caplen(cp, tcp, sizeof(struct tcphdr)) ){
		fprintf(fp, " [Packet size limited during capture]");
		return;
	}

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

	fprintf(fp, " ws=%d seq=%u ack=%u ", ntohs(tcp->window), ntohl(tcp->seq), ntohl(tcp->ack_seq));
	tcp_options(tcp,fp);

	const char* payload = (const char*)tcp + 4*tcp->doff;
	if ( payload_size > 0 && (sport == PORT_DNS || dport == PORT_DNS) ){
		/* offset the length field */
		print_dns(fp, cp, payload + 2, payload_size - 2, flags);
	}
}
