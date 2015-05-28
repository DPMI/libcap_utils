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

static int min(int a, int b){ return a<b?a:b; }

struct dns_header {
	uint16_t id;
	union {
		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint16_t rcode:4;
			uint16_t z:3;
			uint16_t ra:1;
			uint16_t rd:1;
			uint16_t tc:1;
			uint16_t aa:1;
			uint16_t opcode:4;
			uint16_t qr:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint16_t qr:1;
			uint16_t opcode:4;
			uint16_t aa:1;
			uint16_t tc:1;
			uint16_t rd:1;
			uint16_t ra:1;
			uint16_t z:3;
			uint16_t rcode:4;
#endif
		};
		struct {
			uint16_t flags;
		};
	};
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};

enum dns_opcode {
	QUERY = 0,
	IQUERY = 1,
	STATUS = 2,
	NOTIFY = 4,
	UPDATE = 5,
	OPCODE_MAX = 16, /* 4 bits */
};

enum dns_type {
	TYPE_A = 1,
	TYPE_NS = 2,
	TYPE_CNAME = 5,
	TYPE_SOA = 6,
	TYPE_PTR = 12,
	TYPE_MX = 15,
	TYPE_TXT = 16,
	TYPE_AAAA = 28,
	TYPE_SPF = 99,
	TYPE_IXFR = 251,
	TYPE_AXFR = 252,
	TYPE_ANY = 255,
};

enum dns_class {
	CLASS_IN = 1,
	CLASS_CS = 2,
	CLASS_CH = 3,
	CLASS_HS = 4,
	CLASS_MAX
};

enum response_code {
	OK = 0,
	FORMAT_ERROR,
	SERVER_ERROR,
	NAME_ERROR,
	NOT_IMPLEMENTED,
	REFUSED,
	YXDomain,
	YXRRSet,
	NXRRSet,
	NotAuth,
	NotZone
};

static const char* dns_type_lut[TYPE_ANY+1] = {0,};
static const char* dns_class_lut[CLASS_MAX] = {0,};
static const char* dns_opcode_lut[OPCODE_MAX] = {0,};
static int initialized = 0;

static void dns_initialize(){
	dns_type_lut[TYPE_A]     = "A";
	dns_type_lut[TYPE_NS]    = "NS";
	dns_type_lut[TYPE_CNAME] = "CNAME";
	dns_type_lut[TYPE_SOA]   = "SOA";
	dns_type_lut[TYPE_PTR]   = "PTR";
	dns_type_lut[TYPE_MX]    = "MX";
	dns_type_lut[TYPE_TXT]   = "TXT";
	dns_type_lut[TYPE_AAAA]  = "AAAA";
	dns_type_lut[TYPE_SPF]   = "SPF";
	dns_type_lut[TYPE_IXFR]  = "IXFR";
	dns_type_lut[TYPE_AXFR]  = "AXFR";
	dns_type_lut[TYPE_ANY]   = "ANY";
	dns_class_lut[CLASS_IN]  = "IN";
	dns_class_lut[CLASS_CS]  = "CS";
	dns_class_lut[CLASS_CH]  = "CH";
	dns_class_lut[CLASS_HS]  = "HS";
	dns_opcode_lut[QUERY]    = "Query";
	dns_opcode_lut[IQUERY]   = "Inverse query";
	dns_opcode_lut[STATUS]   = "Status";
	dns_opcode_lut[NOTIFY]   = "Notify";
	dns_opcode_lut[UPDATE]   = "Update";
	initialized = 1;
}

static size_t copy_label(char** dst, size_t size, const char* src, size_t len){
	if ( size == 0 ) return 0;

	const int bytes = snprintf(*dst, size, "%.*s.", min(size, len), src);
	*dst += min(bytes,size);

	/* truncated */
	if ( bytes > (int)size ){
		sprintf(*dst-1, "...");
		return size;
	}

	return bytes;
}

static const char* dns_name_int(char** dst, size_t* size, const char* src, const char* payload){
	uint8_t len = *(const uint8_t*)(src++);
	do {

		/* DNS uses a compression algorithm where if the first bits is 0xc0 it is a
		 * reference to a previous label. It should therefore continue to read from
		 * there until len is zero again. */
		if ( (len & 0xc0) == 0xc0 ){
			uint16_t offset = ((len & 0x3f) << 8) + *(const uint8_t*)(src++);
			dns_name_int(dst, size, payload + offset, payload);
			return src;
		}

		/* store the current label */
		*size -= copy_label(dst, *size, src, len);
		src += len;
		len = *(const uint8_t*)(src++);
	} while ( len > 0 );

	return src;
}

/**
 * Extract QNAME from a DNS question section.
 * @param dst Buffer when labels will be written.
 * @param size Number of bytes in dst buffer.
 * @param src Current reading position in packet.
 * @param payload Full packet.
 * @return New position in packet.
 */
static const char* dns_name(char* dst, size_t size, const char* src, const char* payload){
/* small hack to get "..." at the end */
	if ( size != 0 ){
		size -= 3;
	}

	return dns_name_int(&dst, &size, src, payload);
}

static void print_query(FILE* fp, const struct dns_header* h, const char* ptr, const char* payload, unsigned int flags){
	fprintf(fp, " Standard query 0x%04x ", ntohs(h->id));
	for ( unsigned int i = 0; i < ntohs(h->qdcount); i++ ){
		if ( i > 1 ) fputs(", ", fp);
		char qname[128];
		ptr = dns_name(qname, sizeof(qname), ptr, payload);
		uint16_t qtype  = ntohs(*(const uint16_t*)ptr); ptr += 2;
		uint16_t qclass = ntohs(*(const uint16_t*)ptr); ptr += 2;

		fprintf(fp, "%s ", dns_class_lut[qclass]);
		if ( qtype <= TYPE_ANY && dns_type_lut[qtype] ){
			fputs(dns_type_lut[qtype], fp);
		} else {
			fprintf(fp, "(%d)", qtype);
		}

		fprintf(fp, " %s", qname);
	}
}

static void print_response(FILE* fp, const struct dns_header* h, const char* ptr, const char* packet, unsigned int flags){
	fprintf(fp, " Standard query response 0x%04x ", ntohs(h->id));

	/* discard question sections */
	for ( unsigned int i = 0; i < ntohs(h->qdcount); i++ ){
		ptr = dns_name(NULL, 0, ptr, packet);
		ptr += 4; /* +4 to skip qtype and qclass */
	}

	if ( ntohs(h->ancount) == 0 ){
		fprintf(fp, "(no answer section)");
	}

	/* process answer sections */
	for ( unsigned int i = 0; i < ntohs(h->ancount); i++ ){
		char name[128];
		ptr = dns_name(name, sizeof(name), ptr, packet);

		uint16_t type  = ntohs(*(const uint16_t*)ptr); ptr += 2;
		uint16_t class = ntohs(*(const uint16_t*)ptr); ptr += 2;
		uint32_t ttl   = ntohl(*(const uint32_t*)ptr); ptr += 4;
		uint16_t rdlen = ntohs(*(const uint16_t*)ptr); ptr += 2;

		/* hack to silence compiler */
		ttl = ttl;

		if ( type <= TYPE_ANY && dns_type_lut[type] ){
			fprintf(fp, "%s ", dns_type_lut[type]);
		} else {
			fprintf(fp, "(%d) ", type);
		}

		if ( class == CLASS_IN ){
			char buf[INET6_ADDRSTRLEN];
			int tmp;

			switch ( type ){
			case TYPE_A:
				fprintf(fp, "%s ", inet_ntop(AF_INET, ptr, buf, sizeof(buf)));
				break;

			case TYPE_AAAA:
				fprintf(fp, "%s ", inet_ntop(AF_INET6, ptr, buf, sizeof(buf)));
				break;

			case TYPE_MX:
				/* get priority field */
				tmp = ntohs(*(const uint16_t*)ptr);
				fprintf(fp, "%d ", tmp);
				ptr += 2;
				rdlen -= 2;
				/* fall through */

			case TYPE_NS:
			case TYPE_CNAME:
			case TYPE_SOA:
			case TYPE_PTR:
			case TYPE_TXT:
			case TYPE_SPF:
				dns_name(name, sizeof(name), ptr, packet);
				fprintf(fp, " %s ", name);
				break;

			default:
				break;
			}
		} else {
			fprintf(fp, "%s ", dns_class_lut[class]);
		}

		ptr += rdlen;
	}
}

static const char* dns_dump_question(FILE* fp, const char* prefix, unsigned int i, const char* payload, const char* ptr){
	char qname[128];
	ptr = dns_name(qname, sizeof(qname), ptr, payload);
	uint16_t qtype  = ntohs(*(const uint16_t*)ptr); ptr += 2;
	uint16_t qclass = ntohs(*(const uint16_t*)ptr); ptr += 2;

	fprintf(fp, "%sqd[%d]:\n", prefix, i);
	fprintf(fp, "  %sqclass:           %s (%d)\n", prefix, dns_class_lut[qclass], qclass);
	fprintf(fp, "  %sqtype:            ", prefix);
	if ( qtype <= TYPE_ANY && dns_type_lut[qtype] ){
		fprintf(fp, "%s (%d)\n", dns_type_lut[qtype], qtype);
	} else {
		fprintf(fp, "(%d)\n", qtype);
	}
	fprintf(fp, "  %sqname:            %s\n", prefix, qname);

	return ptr;
}

static const char* dns_dump_answer(FILE* fp, const char* prefix, const char* section, unsigned int i, const char* payload, const char* ptr){
	char name[128];
	ptr = dns_name(name, sizeof(name), ptr, payload);
	uint16_t type  = ntohs(*(const uint16_t*)ptr); ptr += 2;
	uint16_t class = ntohs(*(const uint16_t*)ptr); ptr += 2;
	uint32_t ttl   = ntohl(*(const uint32_t*)ptr); ptr += 4;
	uint16_t rdlen = ntohs(*(const uint16_t*)ptr); ptr += 2;

	fprintf(fp, "%s%s[%d]:\n", prefix, section, i);
	fprintf(fp, "  %sclass:            %s (%d)\n", prefix, dns_class_lut[class], class);
	fprintf(fp, "  %stype:             ", prefix);
	if ( type <= TYPE_ANY && dns_type_lut[type] ){
		fprintf(fp, "%s (%d)\n", dns_type_lut[type], type);
	} else {
		fprintf(fp, "(%d)\n", type);
	}
	fprintf(fp, "  %sttl:              %d sec\n", prefix, ttl);
	fprintf(fp, "  %srdlen:            %d octets\n", prefix, rdlen);
	fprintf(fp, "  %sname:             %s\n", prefix, name);

	fprintf(fp, "  %srdata:            ", prefix);
	if ( class == CLASS_IN ){
		char buf[INET6_ADDRSTRLEN];
		int tmp;

		switch ( type ){
		case TYPE_A:
			fprintf(fp, "%s\n", inet_ntop(AF_INET, ptr, buf, sizeof(buf)));
			break;

		case TYPE_AAAA:
			fprintf(fp, "%s\n", inet_ntop(AF_INET6, ptr, buf, sizeof(buf)));
			break;

			case TYPE_MX:
				/* get priority field */
				tmp = ntohs(*(const uint16_t*)ptr);
				fprintf(fp, "%d ", tmp);
				ptr += 2;
				rdlen -= 2;
				/* fall through */

			case TYPE_NS:
			case TYPE_CNAME:
			case TYPE_SOA:
			case TYPE_PTR:
			case TYPE_TXT:
			case TYPE_SPF:
				dns_name(name, sizeof(name), ptr, payload);
				fprintf(fp, "%s\n", name);
				break;

			default:
				break;
			}
		} else {
			fprintf(fp, "%s\n", dns_class_lut[class]);
		}

	return ptr + rdlen;
}

static void dns_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	if ( !initialized ){
		dns_initialize();
	}

	struct dns_header h = *(const struct dns_header*)ptr;
	const char* cur = ptr + sizeof(struct dns_header);
	h.flags = ntohs(h.flags);

	fprintf(fp, "%sid:                 0x%04X\n", prefix, ntohs(h.id));
	fprintf(fp, "%sflags:              0x%04X\n", prefix, h.flags);
	fprintf(fp, "  %sqr:               %d\n", prefix, h.qr);
	fprintf(fp, "  %sopcode:           %s (%d)\n", prefix, dns_opcode_lut[h.opcode], h.opcode);
	fprintf(fp, "  %saa:               %d\n", prefix, h.aa);
	fprintf(fp, "  %stc:               %d\n", prefix, h.tc);
	fprintf(fp, "  %srd:               %d\n", prefix, h.rd);
	fprintf(fp, "  %sra:               %d\n", prefix, h.ra);
	fprintf(fp, "  %sz:                %d\n", prefix, h.z);
	fprintf(fp, "  %srcode:            %d\n", prefix, h.rcode);
	fprintf(fp, "%sqdcount:            %d\n", prefix, ntohs(h.qdcount));
	fprintf(fp, "%sancount:            %d\n", prefix, ntohs(h.ancount));
	fprintf(fp, "%snscount:            %d\n", prefix, ntohs(h.nscount));
	fprintf(fp, "%sarcount:            %d\n", prefix, ntohs(h.arcount));

	const struct cap_header* cp = header->cp;
	if ( cp->caplen < cp->len ){
		fprintf(fp, "%s[Packet size limited during capture]", prefix);
		return;
	}

	for ( unsigned int i = 0; i < ntohs(h.qdcount); i++ ){
		cur = dns_dump_question(fp, prefix, i, ptr, cur);
	}

	for ( unsigned int i = 0; i < ntohs(h.ancount); i++ ){
		cur = dns_dump_answer(fp, prefix, "an", i, ptr, cur);
	}

	for ( unsigned int i = 0; i < ntohs(h.nscount); i++ ){
		cur = dns_dump_answer(fp, prefix, "ns", i, ptr, cur);
	}

	for ( unsigned int i = 0; i < ntohs(h.arcount); i++ ){
		cur = dns_dump_answer(fp, prefix, "ar", i, ptr, cur);
	}
}

static void dns_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	if ( !initialized ){
		dns_initialize();
	}

	struct dns_header h = *(const struct dns_header*)ptr;
	h.flags = ntohs(h.flags);

	const struct cap_header* cp = header->cp;
	const size_t offset         = ptr - cp->payload;     /* how many bytes into the packet are we? */
	const size_t full_size      = cp->len    - offset;   /* how many bytes was the packet? */
	const size_t captured_size  = cp->caplen - offset;   /* how many bytes is left to read? */

	fputs(" DNS", fp);
	if ( flags & FORMAT_HEADER ){
		fprintf(fp, "(HDR[%zd]DATA[%zd])[id=0x%x:qr=%d:opcode=%d,aa=%d,tc=%d,rd=%d,ra=%d,z=%d,rcode=%d]",
		        sizeof(struct dns_header), full_size - sizeof(struct dns_header),
		        ntohs(h.id), h.qr, h.opcode, h.aa, h.tc, h.rd, h.ra, h.z, h.rcode);
	}

	if ( h.tc ){
		fprintf(fp, " message truncated");
		return;
	}

	switch ( (enum response_code)h.rcode ){
	case OK:
		break;

	case FORMAT_ERROR:
		fputs(" Format error", fp);
		return;

	case SERVER_ERROR:
		fputs(" Server failure", fp);
		return;

	case NAME_ERROR:
		fputs(" No such name", fp);
		return;

	case NOT_IMPLEMENTED:
		fputs(" Not implemented", fp);
		return;

	case REFUSED:
		fputs(" Refused", fp);
		return;

	case YXDomain:
		fputs(" Name Exists when it should not", fp);
		return;

	case YXRRSet:
		fputs(" RR Set Exists when it should not", fp);
		return;

	case NXRRSet:
		fputs(" RR Set that should exist does not", fp);
		return;

	case NotAuth:
		fputs(" Not Authoritative", fp);
		return;

	case NotZone:
		fputs(" Name not contained in zone", fp);
		return;

	default:
		fprintf(fp, " rcode: %d", h.rcode);
	}

	if ( full_size > captured_size ){
		fputs(" [Packet size limited during capture]", fp);
		return;
	}

	const char* payload = ptr + sizeof(struct dns_header);
	switch ( h.opcode ){
	case QUERY: /* standard query */
		if ( h.qr == 0 ){
			print_query(fp, &h, payload, ptr, flags);
		} else {
			print_response(fp, &h, payload, ptr, flags);
		}
		break;

	case IQUERY: /* inverse query */
		fprintf(fp, " inverse query");
		break;

	case STATUS:
		fprintf(fp, " status");
		break;

	default:
		fprintf(fp, " reserved opcode %d", h.opcode);
	}
}

struct caputils_protocol protocol_dns = {
	.name = "DNS",
	.size = sizeof(struct dns_header),
	.next_payload = NULL,
	.format = dns_format,
	.dump = dns_dump,
};
