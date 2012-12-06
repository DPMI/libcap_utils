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

#define MAX_ADDRESS 100

struct stream_ethernet {
	struct stream base;
	int socket;
	int port;
	int if_index;
	unsigned int if_mtu;
	struct sockaddr_ll sll;
	struct ether_addr address[MAX_ADDRESS];
	long unsigned int seqnum[MAX_ADDRESS];
	unsigned int num_address;

	size_t num_frames;  /* how many frames that buffer can hold */
	size_t num_packets; /* how many packets is left in current frame */
	char* read_ptr;     /* where inside a frame it currently is */
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
	for ( match = 0; match < st->num_address; match++ ){
		if ( memcmp((const void*)ethhdr->h_dest, st->address[match].ether_addr_octet, ETH_ALEN) == 0 ) break;
	}

	if ( match == st->num_address ){
		return -1; /* ethernet stream did not match any of our expected */
	}

	return match;
}

static int read_packet(struct stream_ethernet* st, struct timeval* timeout){
	assert(st);

	do {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(st->socket, &fds);

		if ( select(st->socket+1, &fds, NULL, NULL, timeout) != 1 ){
			break;
		}

		/* Read data into framebuffer. */
		char* dst = st->frame[st->base.writePos];
		int bytes = recvfrom(st->socket, dst, st->if_mtu, 0, NULL, NULL);
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

    st->base.writePos = (st->base.writePos+1) % st->num_frames;

    /* This indicates a flush from the sender.. */
    if( ntohs(sh->flush) == 1 ){
	    fprintf(stderr, "Sender terminated.\n");
	    st->base.flushed=1;
    }

    return 1;

	} while (1);

	return 0;
}

int stream_ethernet_read(struct stream_ethernet* st, cap_head** header, const struct filter* filter, struct timeval* timeout){
	/* I heard ext is a pretty cool guy, uses goto and doesn't afraid of anything */
  retry:

	/* empty buffer */
	if ( !st->read_ptr ){
		if ( !read_packet(st, timeout) ){
			return EAGAIN;
		}

		char* frame = st->frame[st->base.readPos];
		struct sendhead* sh = (struct sendhead*)(frame + sizeof(struct ethhdr));
		st->read_ptr = frame + sizeof(struct ethhdr) + sizeof(struct sendhead);
		st->num_packets = ntohl(sh->nopkts);
	}

	/* always read if there is space available */
	if ( st->base.writePos != st->base.readPos ){
		struct timeval tv = {0,0}; /* dont read with a timeout as we don't want to introduce delays here */
		read_packet(st, &tv);
	}

	/* no packets available */
	if ( st->num_packets == 0 ){
		fprintf(stderr, "stream_ethernet: st->num_packets is 0 but st->read_ptr is set\n");
		abort();
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

static long stream_ethernet_write(struct stream_ethernet* st, const void* data, size_t size){
	if ( size > st->if_mtu ){
		fprintf(stderr, "packet is larger (%zd) than MTU (%d), ignoring\n", size, st->if_mtu);
		return EINVAL;
	}
  if ( sendto(st->socket, data, size, 0, (struct sockaddr*)&st->sll, sizeof(st->sll)) < 0 ){
    return errno;
  }
  return 0;
}

long stream_ethernet_add(struct stream* stt, const struct ether_addr* addr){
	struct stream_ethernet* st= (struct stream_ethernet*)stt;

	if ( st->num_address == MAX_ADDRESS ){
		return EBUSY;
	}

  /* parse hwaddr from user */
  if ( (addr->ether_addr_octet[0] & 0x01) == 0 ){
    return ERROR_INVALID_HWADDR_MULTICAST;
  }

  /* store parsed address */
  memcpy(&st->address[st->num_address], addr, ETH_ALEN);

  /* setup multicast address */
	struct packet_mreq mcast = {0,};
  mcast.mr_ifindex = st->if_index;
  mcast.mr_type = PACKET_MR_MULTICAST;
  mcast.mr_alen = ETH_ALEN;
  memcpy(mcast.mr_address, &st->address[st->num_address], ETH_ALEN);

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

  st->num_address++;
  return 0;
}

static long stream_ethernet_init(struct stream** stptr, const struct ether_addr* addr, const char* iface, uint16_t proto, size_t buffer_size){
  struct ifreq ifr;

  long ret = 0;

  assert(stptr);

  /* validate arguments */
  if ( !(addr && iface) ){
    return EINVAL;
  }

  /* store the iface name */
  strncpy(ifr.ifr_name, iface, IFNAMSIZ);

  /* open raw socket */
  int fd = socket(AF_PACKET, SOCK_RAW, htons(proto));
  if ( fd < 0 ){
    return errno;
  }

  /* get iface MTU */
  if ( ioctl(fd, SIOCGIFMTU, &ifr) == -1 ){
    return errno;
  }
  unsigned int if_mtu = ifr.ifr_mtu;

  /* query if it is a loopback interface. (loopback captures packets twice, i.e. in both directions) */
  if ( ioctl(fd, SIOCGIFFLAGS, &ifr) == -1 ){
    return errno;
  }
  const int if_loopback = ifr.ifr_flags & IFF_LOOPBACK;

  /* default buffer_size of 25*MTU */
  if ( buffer_size == 0 ){
	  buffer_size = 250 * if_mtu;
  }

  /* ensure buffer is a multiple of MTU and can hold at least one frame */
  if ( buffer_size < if_mtu ){
	  return ERROR_BUFFER_LENGTH;
  } else if ( buffer_size % if_mtu != 0 ){
	  return ERROR_BUFFER_MULTIPLE;
  }

  /* additional memory for the frame pointers */
  size_t frames = buffer_size / if_mtu;
  size_t frame_offset = sizeof(char*) * frames;
  buffer_size += frame_offset;

  /* Initialize the structure */
  if ( (ret = stream_alloc(stptr, PROTOCOL_ETHERNET_MULTICAST, sizeof(struct stream_ethernet), buffer_size) != 0) ){
    return ret;
  }
  struct stream_ethernet* st = (struct stream_ethernet*)*stptr;
  st->socket = fd;
  st->num_address = 0;
  st->if_mtu = if_mtu;
  st->base.if_loopback = if_loopback;
  memset(st->seqnum, 0, sizeof(long unsigned int) * MAX_ADDRESS);

  /* get iface index */
  if ( ioctl(fd, SIOCGIFINDEX, &ifr) == -1 ){
    return errno;
  }
  st->if_index = ifr.ifr_ifindex;

  /* setup buffer pointers (see brief overview at struct declaration) */
  st->num_frames = frames;
  st->num_packets = 0;
  st->read_ptr = NULL;
  st->base.readPos = 0;
  st->base.writePos = 0;
  for ( unsigned int i = 0; i < frames; i++ ){
	  st->frame[i] = st->base.buffer + frame_offset + i * if_mtu;
  }

  /* bind MA MAC */
  if ( ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
	  perror("SIOCGIFHWADDR");
	  return errno;
  }
  memset(&st->sll, 0, sizeof(st->sll));
  st->sll.sll_family=AF_PACKET;
  st->sll.sll_ifindex=st->if_index;
  st->sll.sll_protocol=htons(proto);
  st->sll.sll_pkttype=PACKET_MULTICAST;
  memcpy(st->sll.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
  if ( bind(fd, (struct sockaddr *) &st->sll, sizeof(st->sll)) == -1 ) {
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
