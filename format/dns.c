#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <caputils/log.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <endian.h>

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
	IQUERY,
	STATUS
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

static const char* dns_type_lut[TYPE_ANY+1] = {0,};
static const char* dns_class_lut[CLASS_MAX] = {0,};
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
	initialized = 1;
}

/**
 * Extract QNAME from a DNS question section.
 * @param dst Buffer when labels will be written.
 * @param size Number of bytes in dst buffer.
 * @param src Packet
 * @return New position in packet.
 */
static const char* dns_qname(char* dst, size_t size, const char* src){
	/* small hack to get "..." at the end */
	size -= 3;

	uint8_t len = *(const uint8_t*)(src++);
	do {
		if ( size > 0 ){
			int bytes = snprintf(dst, size, "%.*s.", min(size,len), src);
			dst  += min(bytes,size);
			if ( bytes > (int)size ){ /* truncated */
				bytes = size;
				sprintf(dst-1, "...");
			}
			size -= bytes;
		}
		src += len;
		len = *(const uint8_t*)(src++);
	} while ( len > 0 );

	return src;
}

static void print_query(FILE* fp, const struct dns_header* h, const char* ptr, unsigned int flags){
	fprintf(fp, " Standard query 0x%04x ", ntohs(h->id));
	for ( unsigned int i = 0; i < ntohs(h->qdcount); i++ ){
		if ( i > 1 ) fputs(", ", fp);
		char qname[128];
		ptr = dns_qname(qname, sizeof(qname), ptr);
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

static void print_response(FILE* fp, const struct dns_header* h, const char* ptr, unsigned int flags){
	fprintf(fp, " Standard query response 0x%04x ", ntohs(h->id));
}

void print_dns(FILE* fp, const struct cap_header* cp, const char* payload, size_t size, unsigned int flags){
	if ( !initialized ){
		dns_initialize();
	}

	const size_t bytes = cp->caplen - (payload - cp->payload);
	if ( bytes < sizeof(struct dns_header) ){
		fputs(" DNS [Packet size limited during capture]", fp);
		return;
	}

	struct dns_header h = *(const struct dns_header*)payload;
	h.flags = ntohs(h.flags);

	fputs(" DNS", fp);
	if ( flags & FORMAT_HEADER ){
		fprintf(fp, "(HDR[%zd]DATA[%zd])[id=0x%x:qr=%d:opcode=%d,aa=%d,tc=%d,rd=%d,ra=%d,z=%d,rcode=%d]",
		        sizeof(struct dns_header), size - sizeof(struct dns_header),
		        ntohs(h.id), h.qr, h.opcode, h.aa, h.tc, h.rd, h.ra, h.z, h.rcode);
	}

	if ( h.tc ){
		fprintf(fp, " message truncated");
		return;
	}


	if ( bytes <= size - sizeof(struct dns_header) ){
		fputs(" [Packet size limited during capture]", fp);
		return;
	}

	const char* ptr = payload + sizeof(struct dns_header);
	switch ( h.opcode ){
	case QUERY: /* standard query */
		if ( h.qr == 0 ){
			print_query(fp, &h, ptr, flags);
		} else {
			print_response(fp, &h, ptr, flags);
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
