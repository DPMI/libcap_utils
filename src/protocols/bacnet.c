#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "src/format/format.h"
#include <netinet/udp.h>
#include <stdio.h>
#include <stdint.h>

#define BACNET_BVLC_TYPE 0x81

static enum caputils_protocol_type bacnet_next(struct header_chunk* header, const char* ptr, const char** out) {
	const struct udphdr* udp = (const struct udphdr*)ptr;
	const unsigned char* payload = (const unsigned char*)(udp + 1);

	if (payload[0] == BACNET_BVLC_TYPE) {
		*out = (const char*)(payload + ntohs(udp->len) - sizeof(struct udphdr));
		return PROTOCOL_DATA;
	}

	return PROTOCOL_DONE;
}

static void bacnet_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags) {
	const struct udphdr* udp = (const struct udphdr*)ptr;
	const unsigned char* payload = (const unsigned char*)(udp + 1);

	fprintf(fp, ": BACnet");
	if (payload[0] == BACNET_BVLC_TYPE) {
		fprintf(fp, " (BVLC function 0x%02X)", payload[1]);
	}
}

static void bacnet_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags) {
	const unsigned char* payload = (const unsigned char*)ptr;

	// We can't get payload_len directly, so estimate from caplen
	size_t payload_len = header->cp->caplen - (ptr - header->cp->payload);
	if (payload_len < 4) {
		fprintf(fp, "%sNot a BACnet BVLC packet\n", prefix);
		return;
	}

	uint8_t bvlc_func = payload[1];
	size_t offset = 0;

	if (bvlc_func == 0x0A || bvlc_func == 0x0B) {
		offset = 4;
	} else if (bvlc_func == 0x04) {
		if (payload_len < 10) {
			fprintf(fp, "%sForwarded-NPDU too short\n", prefix);
			return;
		}
		offset = 10;
	} else {
		fprintf(fp, "%sUnsupported BVLC function: 0x%02X\n", prefix, bvlc_func);
		return;
	}

	uint8_t npdu_version = payload[offset++];
	uint8_t npdu_ctrl = payload[offset++];

	fprintf(fp, "%sBVLC Type:          0x%02X\n", prefix, payload[0]);
	fprintf(fp, "%sBVLC Function:      0x%02X\n", prefix, bvlc_func);
	fprintf(fp, "%sBVLC Length:        %u\n", prefix, (payload[2] << 8) | payload[3]);
	fprintf(fp, "%sNPDU Version:       0x%02X\n", prefix, npdu_version);
	fprintf(fp, "%sNPDU Control:       0x%02X\n", prefix, npdu_ctrl);

	// Optional fields depending on control flags
	if (npdu_ctrl & 0x20) {
		if (offset + 3 >= payload_len) return;
		uint8_t dlen = payload[offset + 2];
		offset += 3 + dlen;
		offset += 1; // hop count
	} else if (npdu_ctrl & 0x10) {
		if (offset + 2 >= payload_len) return;
		uint8_t slen = payload[offset + 2];
		offset += 3 + slen;
	} else if (npdu_ctrl & 0x80) {
		fprintf(fp, "%sNo payload\n", prefix);
		return;
	}

	if (offset + 1 >= payload_len) return;

	const unsigned char* apdu = payload + offset;
	size_t apdu_len = payload_len - offset;

	uint8_t apdu_header = apdu[0];
	uint8_t pdu_type = apdu_header >> 4;
	uint8_t pdu_flags = apdu_header & 0x0F;

	fprintf(fp,"%sPDU Type:           %u\n", prefix, pdu_type);
	fprintf(fp,"%sFlags:              %u\n", prefix, pdu_flags);

	if (pdu_type <= 0x07) {
		if (apdu_len >= 2) {
			if (pdu_type == 0x01) {
				fprintf(fp,"%sService Type:       %u\n", prefix, apdu[1]);
			} else if (pdu_type == 0x04) {
				fprintf(fp,"%sInvoke ID:          %u (Segment ACK — no service type)\n", prefix, apdu[1]);
			} else if (apdu_len >= 3) {
				uint8_t service_type = apdu[2];
				fprintf(fp,"%sService Type:       %u\n", prefix, service_type);
				fprintf(fp,"%sInvoke ID:          %u\n", prefix, apdu[1]);
			}
		}
	} else {
		fprintf(fp, "%sNon-BACnet PDU Type: %u — dropping\n", prefix, pdu_type);
		return;
	}
}

// Define the protocol
struct caputils_protocol protocol_bacnet = {
	.name = "BACnet",
	.size = sizeof(struct udphdr),
	.next_payload = bacnet_next,
	.format = bacnet_format,
	.dump = bacnet_dump,
};