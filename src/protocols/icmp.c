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

void print_icmp(FILE* dst, const struct cap_header* cp, net_t net, const struct icmphdr* icmp, unsigned int flags){
	fputs("ICMP", dst);
	if ( flags & FORMAT_HEADER ){
	  fprintf(dst, "[Type=%d, code=%d]", ntohs(icmp->type), ntohs(icmp->code));
	}

	fprintf(dst, ": %s --> %s",  net->net_src, net->net_dst);

	if ( flags < (unsigned int)FORMAT_LAYER_APPLICATION ){
		return;
	}
	fputs(": ", dst);

	switch ( icmp->type ){
	case ICMP_ECHOREPLY:
	  fprintf(dst, "echo reply: %d SEQNR = %d ", ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.sequence));
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
	  fprintf(dst, "echo reqest: %d SEQNR = %d ", ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.sequence));
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

static enum caputils_protocol_type next_payload(struct header_chunk* header, const char* ptr, const char** out){
	return PROTOCOL_DONE;
}

static void icmp_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	//fprintf(fp, "%sip_dst:             %s\n", prefix, dst);
}

struct caputils_protocol protocol_icmp = {
	.name = "ICMP",
	.next_payload = next_payload,
	.format = NULL,
	.dump = icmp_dump,
};
