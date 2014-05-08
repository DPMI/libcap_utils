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
#include <caputils/utils.h>
#include <string.h>

static struct name_table arp_format_table[] = {
	{1, "Ethernet"},
	{0, NULL}, /* sentinel */
};

static struct name_table arp_op_table[] = {
	{1, "ARP Request"},
	{2, "ARP Reply"},
	{3, "RARP Request"},
	{4, "RARP Reply"},
	{8, "InARP Request"},
	{9, "InARP Reply"},
	{10, "ARP NAK"},
	{0, NULL}, /* sentinel */
};

static enum caputils_protocol_type arp_next(struct header_chunk* header, const char* ptr, const char** out){
	return PROTOCOL_DONE;
}

static void arp_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	if ( limited_caplen(header->cp, ptr, sizeof(struct ether_arp)) ){
		fprintf(fp, ": ARP [Packet size limited during capture]");
		return;
	}

	const struct ether_arp* arp = (const struct ether_arp*)ptr;
	fprintf(fp, ": ARP: ");

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
			fputs("Request who-has ", fp);
			fputs(inet_ntoa(tpa.addr), fp);
			fputs(" tell ", fp);
			fputs(inet_ntoa(spa.addr), fp);
			break;

		case ARPOP_REPLY:
			fputs("Reply ", fp);
			fputs(inet_ntoa(spa.addr), fp);
			fputs(" is-at ", fp);
			fputs(hexdump_address((const struct ether_addr*)arp->arp_sha), fp);
			break;

		case ARPOP_RREQUEST:
			fputs("RARP request", fp);
			break;

		case ARPOP_RREPLY:
			fputs("RARP reply", fp);
			break;

		default:
			fprintf(fp, "Unknown op: %d", op);
		}
	} else {
		fprintf(fp, "Unknown format: %d", format);
	}

	fprintf(fp, ", length %zd", header->cp->len - sizeof(struct ethhdr));
}

static void arp_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	if ( limited_caplen(header->cp, ptr, sizeof(struct ethhdr)) ){
		fprintf(fp, "%s[Packet size limited during capture]\n", prefix);
		return;
	}

	const struct ether_arp* arp = (const struct ether_arp*)ptr;
	const int format = ntohs(arp->arp_hrd);
	const int op = ntohs(arp->arp_op);

	fprintf(fp, "%sar_hrd:             %d (%s)\n", prefix, format, name_lookup(arp_format_table, format, "unknown"));
	fprintf(fp, "%sar_pro:             %d\n", prefix, ntohs(arp->arp_pro));
	fprintf(fp, "%sar_hln:             %d bytes\n", prefix, arp->arp_hln);
	fprintf(fp, "%sar_pln:             %d bytes\n", prefix, arp->arp_pln);
	fprintf(fp, "%sar_op:              0x%04x (%s)\n", prefix, op, name_lookup(arp_op_table, op, "unknown"));
}

struct caputils_protocol protocol_arp = {
	.name = "ARP",
	.next_payload = arp_next,
	.format = arp_format,
	.dump = arp_dump,
};
