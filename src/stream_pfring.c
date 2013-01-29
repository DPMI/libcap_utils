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
#endif /* HAVE_CONFIG_H */

#include "caputils/caputils.h"
#include "caputils_int.h"
#include "stream.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pfring.h>
#include <pcap/pcap.h>
#include <pcap/bpf.h>
#include <unistd.h>

#define MAX_ADDRESS 100
#define LIBPFRING_PROMISC 1

struct stream_pfring {
	struct stream base;
	pfring* pd;
	int port;
	int if_mtu;
	struct sockaddr_ll sll;
	struct ether_addr address[MAX_ADDRESS];
	long unsigned int seqnum[MAX_ADDRESS];

	size_t num_frames;  /* how many frames that buffer can hold */
	size_t num_packets; /* how many packets is left in current frame */
	char* read_ptr;     /* where inside a frame it currently is */
	char* frame[0];
};

enum {
	NONBLOCK = 0,
	BLOCK = 1,
};

int valid_framesize(size_t actual, const struct sendhead* sh); /* defined in stream_ethernet.c */

/**
 * Test if a MA packet is valid and matches our expected destinations
 * Returns the matching address index or -1 for invalid packets.
 */
static int match_ma_pkt(const struct stream_pfring* st, const struct ethhdr* ethhdr){
	assert(st);
	assert(ethhdr);

	/* check protocol and destination */
	if ( ntohs(ethhdr->h_proto) != ETHERTYPE_MP ){
		return -1;
	}

	int match;
	for ( match = 0; match < st->base.num_addresses; match++ ){
		if ( memcmp((const void*)ethhdr->h_dest, st->address[match].ether_addr_octet, ETH_ALEN) == 0 ) break;
	}

	if ( match == st->base.num_addresses ){
		return -1; /* ethernet stream did not match any of our expected */
	}

	return match;
}

static int stream_pfring_read_frame(struct stream_pfring* st, int block){
	assert(st);

	do {
		/* read next frame */
		struct pfring_pkthdr hdr;
		switch ( pfring_recv(st->pd, (u_char**)&st->frame[st->base.writePos], 0, &hdr, block) ){
		case 0:
			return 0;
		case 1:
			break;
		case -1:
			fprintf(stderr, "pfring_recv(..) failed.\n");
			return 0;
		}

		char* dst = st->frame[st->base.writePos];

		/* Setup pointers */
		const struct ethhdr* eh = (const struct ethhdr*)dst;
		const struct sendhead* sh = (const struct sendhead*)(dst + sizeof(struct ethhdr));

		/* Check if it is a valid packet and if it was destinationed here */
		int match;
		if ( (match=match_ma_pkt(st, eh)) == -1 ){
			continue;
		}

#ifdef DEBUG
		fprintf(stderr, "got measurement frame with %d capture packets [BU: %3.2f%%]\n", ntohl(sh->nopkts), 0.0f);
#endif

		/* validate frame */
		if ( !valid_framesize(bytes, sh) ){
			/* error message already shown */
			continue;
		}

		/* increase packet count */
		st->base.stat.recv += ntohl(sh->nopkts);

		/* if no sequencenr is set some additional checks are made.
		 * they will also run when the sequence number wraps, but that ok since the
		 * sequence number will match in that case anyway. */
		if ( st->seqnum[match] == 0 ){
			/* read stream version */
			struct file_header_t FH;
			FH.version.major=ntohs(sh->version.major);
			FH.version.minor=ntohs(sh->version.minor);

			/* ensure we can read this version */
			if ( !is_valid_version(&FH) ){
				perror("invalid stream version");
				break;
			}

			/* this is set last, as we want to wait until a packet with valid version
			 * arrives before proceeding. */
			st->seqnum[match] = ntohl(sh->sequencenr);
		}
		match_inc_seqnr(&st->base, &st->seqnum[match], sh);

		st->base.writePos = (st->base.writePos+1) % st->num_frames;

		/* This indicates a flush from the sender.. */
		if( ntohl(sh->flags) & SENDER_FLUSH ){
			fprintf(stderr, "Sender terminated.\n");
			st->base.flushed=1;
		}

		return 1;

	} while (1);

	return 0;
}

int stream_pfring_read(struct stream_pfring* st, cap_head** header, struct filter* filter, struct timeval* timeout){
	/* I heard ext is a pretty cool guy, uses goto and doesn't afraid of anything */
  retry:

	/* empty buffer */
	if ( !st->read_ptr ){
		if ( !stream_pfring_read_frame(st, BLOCK) ){
			return EAGAIN;
		}

		char* frame = st->frame[st->base.readPos];
		struct sendhead* sh = (struct sendhead*)(frame + sizeof(struct ethhdr));
		st->read_ptr = frame + sizeof(struct ethhdr) + sizeof(struct sendhead);
		st->num_packets = ntohl(sh->nopkts);
	}

	/* always read if there is space available */
	if ( st->base.writePos != st->base.readPos ){
		stream_pfring_read_frame(st, NONBLOCK);
	}

	/* no packets available */
	if ( st->num_packets == 0 ){
		return EAGAIN;
	}

	/* fetch next matching packet */
	struct cap_header* cp = (struct cap_header*)(st->read_ptr);
	const size_t packet_size = sizeof(struct cap_header) + cp->caplen;
	st->num_packets--;
	st->read_ptr += packet_size;

	if ( st->num_packets == 0 ){
		st->base.readPos = (st->base.readPos+1) % st->num_frames;
		if ( st->base.readPos == st->base.writePos ){
			st->read_ptr = NULL;
		} else {
			char* frame = st->frame[st->base.readPos];
			struct sendhead* sh = (struct sendhead*)(frame + sizeof(struct ethhdr));
			st->read_ptr = frame + sizeof(struct ethhdr) + sizeof(struct sendhead);
			st->num_packets = ntohl(sh->nopkts);
		}
	}

	if ( cp->caplen == 0 ){
		return ERROR_CAPFILE_INVALID;
	}

	assert(packet_size > 0);

	/* set next packet and advance the read pointer */
	*header = cp;
	st->base.stat.read++;
	st->base.stat.buffer_usage = 0;

	if ( filter && !filter_match(filter, cp->payload, cp) ){
		goto retry;
	}

	st->base.stat.matched++;
	return 0;
}

long stream_pfring_add(struct stream* stt, const struct ether_addr* addr){
	struct stream_pfring* st= (struct stream_pfring*)stt;

	if ( st->base.num_addresses == MAX_ADDRESS ){
		return EBUSY;
	}

	/* parse hwaddr from user */
	if ( (addr->ether_addr_octet[0] & 0x01) == 0 ){
		return ERROR_INVALID_MULTICAST;
	}

	/* store parsed address */
	memcpy(&st->address[st->base.num_addresses], addr, ETH_ALEN);
	st->base.num_addresses++;

	return 0;
}

static long destroy(struct stream_pfring* st){
	free(st->base.comment);
	free(st);
	return 0;
}

long stream_pfring_create(struct stream** stptr, const struct ether_addr* addr, const char* iface, const char* mpid, const char* comment, int flags){
	fprintf(stderr, "libcap_utils with pf_ring does not yet support output streams\n");
	return EINVAL;
}

static int iface_mtu(const char* iface){
	/* store the iface name */
	struct ifreq ifr;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ);

	/* open raw socket */
	int sd = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_MP));
	if ( sd < 0 ){
		return -1;
	}

	/* get iface MTU */
	if ( ioctl(sd, SIOCGIFMTU, &ifr) == -1 ){
		return -1;
	}
	int if_mtu = ifr.ifr_mtu;

	/* close socket */
	close(sd);

	return if_mtu;
}

long stream_pfring_open(struct stream** stptr, const struct ether_addr* addr, const char* iface, size_t buffer_size){
	int ret = 0;
	assert(stptr);

	/* validate arguments */
	if ( !(addr && iface) ){
		return EINVAL;
	}

	/* get MTU for interface */
	const int if_mtu = iface_mtu(iface);
	if ( if_mtu < 0 ){
		return errno;
	}

	pfring_config(99);

	/* open pfring */
	char* derp = strdup(iface);
	pfring* pd = pfring_open(derp, LIBPFRING_PROMISC, if_mtu, 0);
	if ( !pd ){
		return errno;
	}

	pfring_set_application_name(pd, "libcap_utils");

	uint32_t version;
	pfring_version(pd, &version);
	fprintf(stderr, "Using PF_RING v.%d.%d.%d\n",
	        (version & 0xFFFF0000) >> 16,
	        (version & 0x0000FF00) >> 8,
	        version & 0x000000FF);

	if((ret = pfring_set_direction(pd, rx_and_tx_direction)) != 0)
		fprintf(stderr, "pfring_set_direction returned %d (perhaps you use a direction other than rx only with DNA ?)\n", ret);

	if((ret = pfring_set_socket_mode(pd, recv_only_mode)) != 0)
		fprintf(stderr, "pfring_set_socket_mode returned [rc=%d]\n", ret);

	char bpfFilter[] = "ether proto 0x810";
	ret = pfring_set_bpf_filter(pd, bpfFilter);
	if ( ret != 0 ) {
		fprintf(stderr, "pfring_set_bpf_filter(%s) returned %d\n", bpfFilter, ret);
	} else {
		fprintf(stderr, "Successfully set BPF filter '%s'\n", bpfFilter);
	}

	/* default buffer_size of 250*MTU */
	if ( buffer_size == 0 ){
		buffer_size = 250 * sizeof(char*);
	}
	const size_t num_frames = buffer_size / sizeof(char*);

	/* Initialize the structure */
	if ( (ret = stream_alloc(stptr, PROTOCOL_ETHERNET_MULTICAST, sizeof(struct stream_pfring), buffer_size, if_mtu) != 0) ){
		return ret;
	}
	struct stream_pfring* st = (struct stream_pfring*)*stptr;
	st->pd = pd;
	st->if_mtu = if_mtu;
	memset(st->seqnum, 0, sizeof(long unsigned int) * MAX_ADDRESS);

	if (pfring_enable_ring(pd) != 0) {
		fprintf(stderr, "Unable to enable ring :-(\n");
		pfring_close(pd);
		return(-1);
	}

	/* setup buffer pointers (see brief overview at struct declaration) */
	st->num_frames = num_frames;
	st->num_packets = 0;
	st->read_ptr = NULL;
	st->base.readPos = 0;
	st->base.writePos = 0;
	for ( unsigned int i = 0; i < num_frames; i++ ){
		st->frame[i] = NULL;
	}

	/* add membership to group */
	if ( (ret=stream_pfring_add(&st->base, addr)) != 0 ){
		return ret;
	}

/*
  if ( (ret=stream_pfring_init(stptr, addr, iface, ETH_P_ALL, buffer_size)) != 0 ){
  return ret;
  }
*/
	st->base.type = PROTOCOL_ETHERNET_MULTICAST;
	st->base.FH.comment_size = 0;
	st->base.comment = NULL;

	/* callbacks */
	st->base.fill_buffer = NULL;
	st->base.destroy = (destroy_callback)destroy;
	st->base.write = NULL;
	st->base.read = (read_callback)stream_pfring_read;

	return 0;
}

/* I CAN HAZ PASTA PLOX? */
int pcap_compile_nopcap(int snaplen_arg, int linktype_arg,
                        struct bpf_program *program,
                        const char *buf, int optimize, bpf_u_int32 mask)
{
	pcap_t *p;
	int ret;

	p = pcap_open_dead(linktype_arg, snaplen_arg);
	if (p == NULL)
		return (-1);
	ret = pcap_compile(p, program, buf, optimize, mask);
	if ( ret != 0 ){
		fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(p));
	}
	pcap_close(p);
	return (ret);
}

/*
  static int stream_add(struct stream* st, const stream_addr_t* addr){
  if ( !st || stream_addr_type(addr) != STREAM_ADDR_ETHERNET ){
  return EINVAL;
  }

  if ( st->type != PROTOCOL_ETHERNET_MULTICAST ){
  return ERROR_INVALID_PROTOCOL;
  }

  struct stream_pfring* se = (struct stream_pfring*)st;
  return stream_pfring_add(se, &addr->ether_addr);
  }
*/
