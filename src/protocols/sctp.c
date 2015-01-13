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

/* Section 3.1.  SCTP Common Header Format */
typedef struct sctphdr {
         uint16_t source;
         uint16_t dest;
         uint32_t vtag;
         uint32_t checksum;
} __attribute__((packed)) sctp_sctphdr_t;

typedef struct sctp_chunkhdr {
  uint8_t type;
  uint8_t flags;
  uint16_t length;
} __attribute__((packed)) sctp_chunkhdr_t;




static void sctp_chunks(const struct cap_header* cp,const struct sctphdr* sctp, int chunksize, FILE* dst){


	fprintf(dst,": (in development) ");
	const uint8_t* ptr = (const u_int8_t*)((const char*)sctp) + sizeof(struct sctphdr);
	int chunkread=0;


	while ( ptr != 0 ){
	  const sctp_chunkhdr_t* chunk = (const sctp_chunkhdr_t*)ptr;
	  switch(ntohs(chunk->type)){
	  case 0:
	    fprintf(dst,"DATA %d bytes, ",ntohs(chunk->length));
	    break;
	  case 1:
	    fprintf(dst,"INIT %d bytes, ",ntohs(chunk->length));
	    break;
	  case 2:
	    fprintf(dst,"INIT ACK %d bytes, ",ntohs(chunk->length));
	    break;
	  case 3:
	    fprintf(dst,"SACK %d bytes, ",ntohs(chunk->length));
	    break;	    
	  case 4:
	    fprintf(dst,"HEARTBEAT %d bytes, ",ntohs(chunk->length));
	    break;
	  case 5:
	    fprintf(dst,"HEARTBEAT ACK %d bytes, ",ntohs(chunk->length));
	    break;
	  case 6:
	    fprintf(dst,"ABORT %d bytes, ",ntohs(chunk->length));
	    break;
	  case 7:
	    fprintf(dst,"SHUTDOWN %d bytes, ",ntohs(chunk->length));
	    break;
	  case 8:
	    fprintf(dst,"SHUTDOWN ACK %d bytes, ",ntohs(chunk->length));
	    break;
	  case 9:
	    fprintf(dst,"ERROR %d bytes, ",ntohs(chunk->length));
	    break;
	  case 10:
	    fprintf(dst,"COOKIE ECHO %d bytes, ",ntohs(chunk->length));
	    break;
	  case 11:
	    fprintf(dst,"COOKIE ACK %d bytes, ",ntohs(chunk->length));
	    break;
	  case 12:
	    fprintf(dst,"ECNE %d bytes, ",ntohs(chunk->length));
	    break;
	  case 13:
	    fprintf(dst,"CWR %d bytes, ",ntohs(chunk->length));
	    break;
	  case 14:
	    fprintf(dst,"SHUTDOWN COMPLETE %d bytes, ",ntohs(chunk->length));
	    break;
	  default:
	    fprintf(dst,"Type=%" PRIu8 ", length=%u bytes ",ntohs(chunk->type),ntohs(chunk->length));
	    break;
	  }
	  
	  /*read next chunk */
	  ptr += sizeof(struct sctp_chunkhdr) + chunk->length;
	  chunkread += sizeof(struct sctp_chunkhdr) + chunk->length;
	  if(chunkread>= chunksize) {
	    ptr=0;
	  }
	}
	
}


static enum caputils_protocol_type sctp_next(struct header_chunk* header, const char* ptr, const char** out){
  /*
    Do not look for data after SCTP message, chunks... handled differently 
    */
  return PROTOCOL_DONE; 
  
}


static void sctp_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	fputs(": SCTP", fp);

	if ( limited_caplen(header->cp, ptr, sizeof(struct sctphdr)) ){
		fputs(" [Packet size limited during capture]", fp);
		return;
	}

	const struct sctphdr* sctp = (const struct sctphdr*)ptr;
	const size_t header_size = 12;
	const size_t payload_size = header->last_net.plen - header_size;
	if ( flags & FORMAT_HEADER ){
		fprintf(fp, "(HDR[%zd]DATA[%zd])", header_size, payload_size);
	}

	const uint16_t sport = ntohs(sctp->source);
	const uint16_t dport = ntohs(sctp->dest);

	fprintf(fp, ": %s:%d --> %s:%d", header->last_net.net_src, sport, header->last_net.net_dst, dport);
	sctp_chunks(header->cp, sctp, payload_size, fp);
}

static void sctp_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	if ( limited_caplen(header->cp, ptr, sizeof(struct sctphdr)) ){
		fprintf(fp, "%s[Packet size limited during capture]", prefix);
		return;
	}

	const struct sctphdr* sctp = (const struct sctphdr*)ptr;
	fprintf(fp, "%ssource:             %d\n", prefix, ntohs(sctp->source));
	fprintf(fp, "%sdest:               %d\n", prefix, ntohs(sctp->dest));
	fprintf(fp, "%sseq:                %u\n", prefix, ntohl(sctp->vtag));
	fprintf(fp, "%sseq_ack:            %u\n", prefix, ntohl(sctp->checksum));
}

struct caputils_protocol protocol_sctp = {
	.name = "SCTP",
	.size = sizeof(struct sctphdr),
	.next_payload = sctp_next,
	.format = sctp_format,
	.dump = sctp_dump,
};
