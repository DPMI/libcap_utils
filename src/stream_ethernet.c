#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "caputils/caputils.h"
#include "caputils/interface.h"
#include "caputils_int.h"
#include "stream.h"
#include "stream_buffer.h"
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

#define MAX_ADDRESS 100

struct stream_ethernet {
	struct stream base;
	int socket;
	int port;
	int if_index;
	struct sockaddr_ll sll;
	struct ether_addr address[MAX_ADDRESS];
	long unsigned int seqnum[MAX_ADDRESS];

	struct stream_frame_buffer fb;
	char* frame[0];
};

/**
 * Test if a MA packet is valid and matches our expected destinations
 * Returns the matching address index or -1 for invalid packets.
 */
static int match_ma_pkt(const struct stream_ethernet* st, const struct ethhdr* ethhdr){
	assert(st);
	assert(ethhdr);

	/* check protocol and destination */
	if ( ntohs(ethhdr->h_proto) != ETHERTYPE_MP ){
		return -1;
	}

	unsigned int match;
	for ( match = 0; match < st->base.num_addresses; match++ ){
		if ( memcmp((const void*)ethhdr->h_dest, st->address[match].ether_addr_octet, ETH_ALEN) == 0 ) break;
	}

	if ( match == st->base.num_addresses ){
		return -1; /* ethernet stream did not match any of our expected */
	}

	return match;
}

static int stream_ethernet_read_frame(struct stream_ethernet* st, char* dst, struct timeval* timeout){
	assert(st);
	assert(dst);

	do {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(st->socket, &fds);

		if ( select(st->socket+1, &fds, NULL, NULL, timeout) != 1 ){
			break;
		}

		/* Read data into framebuffer. */
		int bytes = recvfrom(st->socket, dst, st->base.if_mtu, 0, NULL, NULL);
		if ( bytes < 0 ){ /* error occurred */
			perror("Cannot receive Ethernet data.");
			break;
		} else if ( bytes == 0 ){ /* proper shutdown */
			perror("Connection closed by client.");
			break;
		}

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
		fprintf(stderr, "  address: %s (%d)\n", hexdump_address(&st->address[match]), match);
#endif

		/* quick sanity check */
		if ( bytes < (int)ntohl(sh->nopkts) ){
			fprintf(stderr, "invalid measurement frame received.\n"
			        "  seqnum: 0x%04X [raw: 0x%08X]\n"
			        "  nopkts: %d [raw: 0x%08X]\n"
			        "  frame size: %d bytes\n",
			        ntohl(sh->sequencenr), sh->sequencenr, ntohl(sh->nopkts), sh->nopkts, bytes);
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

		/* This indicates a flush from the sender.. */
		if( ntohs(sh->flush) == 1 ){
			fprintf(stderr, "Sender terminated.\n");
			st->base.flushed=1;
		}

		return 1;

	} while (1);

	return 0;
}

int stream_ethernet_read(struct stream_ethernet* st, cap_head** cp, struct filter* filter, struct timeval* timeout){
	return stream_frame_buffer_read(&st->base, &st->fb, cp, filter, timeout);
}

static long stream_ethernet_write(struct stream_ethernet* st, const void* data, size_t size){
	if ( size > st->base.if_mtu ){
		fprintf(stderr, "packet is larger (%zd) than MTU (%zd), ignoring\n", size, st->base.if_mtu);
		return EINVAL;
	}
	if ( sendto(st->socket, data, size, 0, (struct sockaddr*)&st->sll, sizeof(st->sll)) < 0 ){
		return errno;
	}
	return 0;
}

long stream_ethernet_add(struct stream* stt, const struct ether_addr* addr){
	struct stream_ethernet* st= (struct stream_ethernet*)stt;

	if ( st->base.num_addresses == MAX_ADDRESS ){
		return EBUSY;
	}

	/* parse hwaddr from user */
	if ( (addr->ether_addr_octet[0] & 0x01) == 0 ){
		return ERROR_INVALID_MULTICAST;
	}

	/* store parsed address */
	memcpy(&st->address[st->base.num_addresses], addr, ETH_ALEN);

	/* setup multicast address */
	struct packet_mreq mcast = {0,};
	mcast.mr_ifindex = st->if_index;
	mcast.mr_type = PACKET_MR_MULTICAST;
	mcast.mr_alen = ETH_ALEN;
	memcpy(mcast.mr_address, &st->address[st->base.num_addresses], ETH_ALEN);

#ifdef DEBUG
	char name[IF_NAMESIZE+1];
	char eth_src[IFHWADDRLEN*3];
	char eth_dst[IFHWADDRLEN*3];
	fprintf(stderr, "Adding membership to ethernet multicast group:\n"
	        "\tEthernet.type=%04X\n"
	        "\tEthernet.src=%s\n"
	        "\tEthernet.dst=%s\n"
	        "\tInterface=%s (%d)\n",
	        ETHERTYPE_MP,
	        hexdump_address_r(&st->sll.sll_addr, eth_src),
	        hexdump_address_r(&mcast.mr_address, eth_dst),
	        if_indextoname(st->if_index, name), mcast.mr_ifindex);
#endif

	/* setup ethernet multicast */
	if ( setsockopt(st->socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void*)&mcast, sizeof(mcast)) == -1 ){
		perror("Adding multicast address failed");
		return errno;
	}

	st->base.num_addresses++;
	return 0;
}

static int stream_ethernet_init(struct stream** stptr, const struct ether_addr* addr, const char* iface, uint16_t proto, size_t buffer_size){
	struct iface ifstat;
	int ret = 0;

	/* validate arguments */
	assert(stptr);
	if ( !(addr && iface) ){
		return EINVAL;
	}

	/* query interface properties */
	if ( (ret=iface_get(iface, &ifstat)) != 0 ){
		return ret;
	}

	const unsigned int if_mtu = ifstat.if_mtu;

	/* default buffer_size of 250*MTU */
	if ( buffer_size == 0 ){
		buffer_size = 250 * if_mtu;
	}

	/* ensure buffer is a multiple of MTU and can hold at least one frame */
	if ( buffer_size < if_mtu ){
		return ERROR_BUFFER_LENGTH;
	} else if ( buffer_size % if_mtu != 0 ){
		return ERROR_BUFFER_MULTIPLE;
	}

	/* slightly backwards calculation, but user want to enter buffer size in bytes (and it maintains compatibility) */
	const size_t num_frames = buffer_size / if_mtu;
	buffer_size = stream_frame_buffer_size(num_frames, if_mtu);

	/* Initialize stream */
	if ( (ret = stream_alloc(stptr, PROTOCOL_ETHERNET_MULTICAST, sizeof(struct stream_ethernet), buffer_size, if_mtu) != 0) ){
		return ret;
	}
	struct stream_ethernet* st = (struct stream_ethernet*)*stptr;
	stream_frame_init(&st->fb, (read_frame_callback)stream_ethernet_read_frame, (char*)st->frame, num_frames, if_mtu);

	/* open raw socket */
	if ( (st->socket=socket(AF_PACKET, SOCK_RAW, htons(proto))) < 0 ){
		return errno;
	}

	st->fb.header_offset = sizeof(struct ethhdr);
	st->if_index = ifstat.if_index;
	st->base.if_loopback = ifstat.if_loopback;
	memset(st->seqnum, 0, sizeof(long unsigned int) * MAX_ADDRESS);

	/* bind MA MAC */
	memset(&st->sll, 0, sizeof(st->sll));
	st->sll.sll_family=AF_PACKET;
	st->sll.sll_ifindex=st->if_index;
	st->sll.sll_protocol=htons(proto);
	st->sll.sll_pkttype=PACKET_MULTICAST;
	memcpy(st->sll.sll_addr, &ifstat.if_hwaddr, ETH_ALEN);
	if ( bind(st->socket, (struct sockaddr *) &st->sll, sizeof(st->sll)) == -1 ) {
		perror("Binding to interface.");
		return errno;
	}

	/* add membership to group */
	if ( (ret=stream_ethernet_add(&st->base, addr)) != 0 ){
		return ret;
	}

	return 0;
}

static long destroy(struct stream_ethernet* st){
	free(st->base.comment);
	free(st);
	return 0;
}

long stream_ethernet_create(struct stream** stptr, const struct ether_addr* addr, const char* iface, const char* mpid, const char* comment, int flags){
	long ret = 0;

	if ( (ret=stream_ethernet_init(stptr, addr, iface, ETHERTYPE_MP, 0)) != 0 ){
		return ret;
	}

	struct stream_ethernet* st = (struct stream_ethernet*)*stptr;

	st->base.FH.comment_size = strlen(comment);
	st->base.comment = strdup(comment);

	/* callbacks */
	st->base.fill_buffer = NULL;
	st->base.destroy = (destroy_callback)destroy;
	st->base.write = (write_callback)stream_ethernet_write;

	return 0;
}

long stream_ethernet_open(struct stream** stptr, const struct ether_addr* addr, const char* iface, size_t buffer_size){
	long ret = 0;

	if ( (ret=stream_ethernet_init(stptr, addr, iface, ETH_P_ALL, buffer_size)) != 0 ){
		return ret;
	}

	struct stream_ethernet* st = (struct stream_ethernet*)*stptr;

	st->base.type = PROTOCOL_ETHERNET_MULTICAST;
	st->base.FH.comment_size = 0;
	st->base.comment = NULL;

	/* callbacks */
	st->base.fill_buffer = NULL;
	st->base.destroy = (destroy_callback)destroy;
	st->base.write = NULL;
	st->base.read = (read_callback)stream_ethernet_read;

	return 0;
}
