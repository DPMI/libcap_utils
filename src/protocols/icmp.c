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

static struct name_table icmp_unreachable_table[] = {
 		{ICMP_NET_UNREACH,    "Destination network unreachable"},
		{ICMP_HOST_UNREACH,   "Destination host unreachable"},
		{ICMP_PROT_UNREACH,   "Destination protocol unreachable"},
		{ICMP_PORT_UNREACH,   "Destination port unreachable"},
		{ICMP_FRAG_NEEDED,    "Fragmentation required"},
		{ICMP_SR_FAILED,      "Source route failed"},
		{ICMP_NET_UNKNOWN,    "Destination network unknown"},
		{ICMP_HOST_UNKNOWN,   "Destination host unknown"},
		{ICMP_HOST_ISOLATED,  "Source host isolated"},
		{ICMP_NET_ANO,        "Network administratively prohibited"},
		{ICMP_HOST_ANO,       "Host administratively prohibited"},
		{ICMP_NET_UNR_TOS,    "Network unreachable for TOS"},
		{ICMP_HOST_UNR_TOS,   "Host unreachable for TOS"},
		{ICMP_PKT_FILTERED,   "Communication administratively prohibited"},
		{ICMP_PREC_VIOLATION, "Host Precedence Violation"},
		{ICMP_PREC_CUTOFF,    "Precedence cutoff in effect"},
};

static void icmp_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	const struct icmphdr* icmp = (const struct icmphdr*)ptr;

	fputs(": ICMP", fp);
	if ( flags & FORMAT_HEADER ){
	  fprintf(fp, "[Type=%d, code=%d]", ntohs(icmp->type), ntohs(icmp->code));
	}

	fprintf(fp, ": %s --> %s",  header->last_net.net_src, header->last_net.net_dst);

	if ( flags < (unsigned int)FORMAT_LAYER_APPLICATION ){
		return;
	}
	fputs(": ", fp);

	switch ( icmp->type ){
	case ICMP_ECHOREPLY:
	  fprintf(fp, "echo reply: %d SEQNR = %d ", ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.sequence));
		break;

	case ICMP_DEST_UNREACH:
		fprintf(fp, "%s", name_lookup(icmp_unreachable_table, icmp->code, "Destination Unreachable"));
		break;

	case ICMP_SOURCE_QUENCH:
		fprintf(fp, "source quench");
		break;

	case ICMP_REDIRECT:
		fprintf(fp, "redirect");
		break;

	case ICMP_ECHO:
	  fprintf(fp, "echo reqest: %d SEQNR = %d ", ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.sequence));
		break;

	case ICMP_TIME_EXCEEDED:
		fprintf(fp, "time exceeded");
		break;

	case ICMP_TIMESTAMP:
		fprintf(fp, "timestamp request");
		break;

	case ICMP_TIMESTAMPREPLY:
		fprintf(fp, "timestamp reply");
		break;

	default:
		fprintf(fp, "Type %d\n", icmp->type);
	}
}

static enum caputils_protocol_type next_payload(struct header_chunk* header, const char* ptr, const char** out){
	return PROTOCOL_DONE;
}

static void icmp_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	const struct icmphdr* icmp = (const struct icmphdr*)ptr;

	fprintf(fp, "%stype:               %d\n", prefix, icmp->type);
	fprintf(fp, "%scode:               %d\n", prefix, icmp->code);
}

struct caputils_protocol protocol_icmp = {
	.name = "ICMP",
	.size = sizeof(struct icmphdr),
	.next_payload = next_payload,
	.format = icmp_format,
	.dump = icmp_dump,
};
