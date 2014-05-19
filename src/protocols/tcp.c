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

#include "src/format/format.h"

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

static size_t tcp_option_size(const tcp_option_t* opt){
	switch ( opt->kind ){
	case EOL:
	case NOP:
		return 1;

	default:
		return opt->size;
	}
}

static void tcp_options(const struct cap_header* cp,const struct tcphdr* tcp, FILE* dst){
	if ( tcp->doff <= 5 ) return; /* no options present */

	fprintf(dst,"|");
	const uint8_t* ptr = (const u_int8_t*)((const char*)tcp) + sizeof(struct tcphdr);

	int optlen = sizeof(struct tcphdr);
	while ( *ptr != 0 && optlen < 4*tcp->doff ){
		const tcp_option_t* opt = (const tcp_option_t*)ptr;

		/* Ensure there is enough data left in packet. (used + 1) is used to tell if
		 * there is enough data to read option kind. */
		const size_t used = (const char*)ptr - cp->payload;
		if (
			(used + 1) > cp->caplen ||                              /* ensure option kind is present */
			(used + (opt->kind > NOP ? 2 : 1)) > cp->caplen ||      /* ensure option size is present if needed */
			(used + tcp_option_size(opt)) > cp->caplen ){           /* ensure option data is present */

			fprintf(dst,"tcp option truncated (caplen)");
			break;
		}

		if ( tcp_option_size(opt) == 0 ){
			fprintf(dst, "invalid flag size 0 (kind: %d), aborting\n", opt->kind);
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
	tcp_options(cp,tcp,fp);

	const char* payload = (const char*)tcp + 4*tcp->doff;
	if ( payload_size == 0 ) return;

	if ( (sport == PORT_DNS || dport == PORT_DNS) ) {
		/* offset the length field */
		print_dns(fp, cp, payload + 2, payload_size - 2, flags);
	}

	if ( (sport == PORT_HTTP || dport == PORT_HTTP) ) {
		print_http(fp, cp, payload, payload_size, flags);
	}
}

static enum caputils_protocol_type next_payload(struct header_chunk* header, const char* ptr, const char** out){
	if ( limited_caplen(header->cp, ptr, sizeof(struct tcphdr)) ){
		return PROTOCOL_DONE;
	}

	const struct tcphdr* tcp = (const struct tcphdr*)ptr;
	const size_t header_size = 4*tcp->doff;
	const size_t payload_size = header->last_net.plen - header_size;
	*out = ptr + header_size;
	if ( payload_size == 0 ){
		return PROTOCOL_DONE;
	}
	return PROTOCOL_DATA;
}


static void tcp_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	fputs(": TCP", fp);
	
	if ( limited_caplen(header->cp, ptr, sizeof(struct tcphdr)) ){
		fputs(" [Packet size limited during capture]", fp);
		return;
	}
	
	const struct tcphdr* tcp = (const struct tcphdr*)ptr;
	const size_t header_size = 4*tcp->doff;
	const size_t payload_size = header->last_net.plen - header_size;
	if ( flags & FORMAT_HEADER ){
		fprintf(fp, "(HDR[%zd]DATA[%zd])", header_size, payload_size);
	}

	const uint16_t sport = ntohs(tcp->source);
	const uint16_t dport = ntohs(tcp->dest);

	fprintf(fp, ": [%s] %s:%d --> %s:%d", tcp_flags(tcp),
	        header->last_net.net_src, sport,
	        header->last_net.net_dst, dport);

	fprintf(fp, " ws=%d seq=%u ack=%u ", ntohs(tcp->window), ntohl(tcp->seq), ntohl(tcp->ack_seq));
	tcp_options(header->cp, tcp, fp);

		const char* payload = (const char*)tcp + 4*tcp->doff;
	if ( payload_size == 0 ) return;

	if ( (sport == PORT_DNS || dport == PORT_DNS) ) {
		/* offset the length field */
		print_dns(fp, header->cp, payload + 2, payload_size - 2, flags);
	}

	if ( (sport == PORT_HTTP || dport == PORT_HTTP) ) {
		print_http(fp, header->cp, payload, payload_size, flags);
	}
       		
}

static void tcp_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	if ( limited_caplen(header->cp, ptr, sizeof(struct tcphdr)) ){
		fprintf(fp, "%s[Packet size limited during capture]", prefix);
		return;
	}

	const struct tcphdr* tcp = (const struct tcphdr*)ptr;
	fprintf(fp, "%ssource:             %d\n", prefix, ntohs(tcp->source));
	fprintf(fp, "%sdest:               %d\n", prefix, ntohs(tcp->dest));
	fprintf(fp, "%sseq:                %u\n", prefix, ntohl(tcp->seq));
	fprintf(fp, "%sseq_ack:            %u\n", prefix, ntohl(tcp->ack_seq));
	fprintf(fp, "%sdoff:               %d\n", prefix, tcp->doff);
	fprintf(fp, "%sdoff:               %d\n", prefix, tcp->doff);
	fprintf(fp, "%sres1:               0x%x\n", prefix, tcp->res1);
	fprintf(fp, "%sres2:               0x%x\n", prefix, tcp->res2);
	fprintf(fp, "%surg:                %d\n", prefix, tcp->urg);
	fprintf(fp, "%sack:                %d\n", prefix, tcp->ack);
	fprintf(fp, "%spsh:                %d\n", prefix, tcp->psh);
	fprintf(fp, "%srst:                %d\n", prefix, tcp->rst);
	fprintf(fp, "%ssyn:                %d\n", prefix, tcp->syn);
	fprintf(fp, "%sfin:                %d\n", prefix, tcp->fin);
	fprintf(fp, "%swindow:             %u\n", prefix, ntohs(tcp->window));
	fprintf(fp, "%scheck:              0x%04x\n", prefix, ntohs(tcp->check));
	fprintf(fp, "%surg:                %u\n", prefix, ntohs(tcp->urg_ptr));
}

struct caputils_protocol protocol_tcp = {
	.name = "TCP",
	.next_payload = next_payload,
	.format = tcp_format,
	.dump = tcp_dump,
};
