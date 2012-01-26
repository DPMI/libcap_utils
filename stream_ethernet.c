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
  int if_mtu;
  struct sockaddr_ll sll;
  struct ether_addr address[MAX_ADDRESS];
	long unsigned int seqnum[MAX_ADDRESS];
	unsigned int num_address;
};

/**
 * Test if a MA packet is valid and matches our expected destinations
 * Returns the matching address index or -1 for invalid packets.
 */
static int match_ma_pkt(const struct stream_ethernet* st, const struct ethhdr* ethhdr){
	assert(st);
	assert(ethhdr);

	/* check protocol and destination */
	if ( ntohs(ethhdr->h_proto) != LLPROTO ){
		return -1;
	}

	int match;
	for ( match = 0; match < st->num_address; match++ ){
		if ( memcmp((const void*)ethhdr->h_dest, st->address[match].ether_addr_octet, ETH_ALEN) == 0 ) break;
	}

	if ( match == st->num_address ){
		return -1; /* ethernet stream did not match any of our expected */
	}

	return match;
}

static int fill_buffer(struct stream_ethernet* st, struct timeval* timeout){
	assert(st);

	int total_bytes = 0;
  size_t available = buffLen;
  size_t offset = 0;

  /* copy old content */
  if ( st->base.readPos > 0 ){
    const size_t bytes = st->base.bufferSize - st->base.readPos;
    memmove(st->base.buffer, st->base.buffer + st->base.readPos, bytes); /* move content */
    st->base.bufferSize = bytes;
    st->base.readPos = 0;
    available = buffLen - bytes;
    offset = bytes;
  }

  assert(available >= st->if_mtu);

  while ( available >= st->if_mtu ){
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(st->socket, &fds);
    
    switch ( select(st->socket+1, &fds, NULL, NULL, timeout) ){
    case -1:
      return -1;
    case 0:
      errno = EAGAIN;
      return -1;
    case 1:
      break;
    }

    /* Read data into a temporary buffer. */
    char temp[st->if_mtu];
    int bytes = recvfrom(st->socket, temp, st->if_mtu, 0, NULL, NULL);
    if ( bytes < 0 ){ /* error occurred */
      perror("Cannot receive Ethernet data.");
      return -1;
    } else if ( bytes == 0 ){ /* proper shutdown */
      perror("Connection closed by client.");
      return -1; /* return -1 so it won't try again */
    }

    /* Setup pointers */
    const struct ethhdr* eh = (const struct ethhdr*)temp;
    const struct sendhead* sh = (const struct sendhead*)(temp + sizeof(struct ethhdr));

    /* Check if it is a valid packet and if it was destinationed here */
    int match;
    if ( (match=match_ma_pkt(st, eh)) == -1 ){
	    continue;
    }

    /* increase packet count */
    st->base.pktCount += ntohs(sh->nopkts);

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
	      return -1;
      }

      /* this is set last, as we want to wait until a packet with valid version
       * arrives before proceeding. */
      st->seqnum[match] = ntohl(sh->sequencenr);
    }
    match_inc_seqnr(&st->seqnum[match], sh);

    /* copy packets to stream buffer */
    const size_t header_size = sizeof(struct ethhdr) + sizeof(struct sendhead);
    const size_t capture_bytes = bytes - header_size;
    memcpy(st->base.buffer + offset, temp + header_size, capture_bytes);
    st->base.bufferSize += capture_bytes;
    available -= capture_bytes;
    offset += capture_bytes;
    total_bytes += capture_bytes;

#ifdef DEBUG
    fprintf(stderr, "got measurement frame with %d capture packets [BU: %3.2f%%]\n", ntohl(sh->nopkts), (float)offset / buffLen * 100);
#endif

    /* This indicates a flush from the sender.. */
    if( ntohs(sh->flush) == 1 ){
	    fprintf(stderr, "Sender terminated.\n");
	    st->base.flushed=1;
    }
  }

  return total_bytes;
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

static long stream_ethernet_add(struct stream_ethernet* st, const struct ether_addr* addr){
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
          LLPROTO,
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

static long stream_ethernet_init(struct stream** stptr, const struct ether_addr* addr, const char* iface, uint16_t proto){
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

  /* Initialize the structure */
  if ( (ret = stream_alloc(stptr, PROTOCOL_ETHERNET_MULTICAST, sizeof(struct stream_ethernet)) != 0) ){
    return ret;
  }
  struct stream_ethernet* st = (struct stream_ethernet*)*stptr;
  st->socket = fd;
  st->num_address = 0;

  /* get iface index */
  if ( ioctl(fd, SIOCGIFINDEX, &ifr) == -1 ){
    return errno;
  }
  st->if_index = ifr.ifr_ifindex;

  /* get iface MTU */
  if ( ioctl(fd, SIOCGIFMTU, &ifr) == -1 ){
    return errno;
  }
  st->if_mtu = ifr.ifr_mtu;

  /* ensure buffer is larger than MTU */
  if ( buffLen < st->if_mtu ){
	  return ERROR_BUFFER_LENGTH;
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
  if ( (ret=stream_ethernet_add(st, addr)) != 0 ){
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

  if ( (ret=stream_ethernet_init(stptr, addr, iface, LLPROTO)) != 0 ){
    return ret;
  }

  struct stream_ethernet* st = (struct stream_ethernet*)*stptr;  

  st->base.FH.comment_size = strlen(comment);
  st->base.comment = strdup(comment);

  /* callbacks */
  st->base.fill_buffer = (fill_buffer_callback)fill_buffer;
  st->base.destroy = (destroy_callback)destroy;
  st->base.write = (write_callback)stream_ethernet_write;

  return 0;
}

long stream_ethernet_open(struct stream** stptr, const struct ether_addr* addr, const char* iface){
  long ret = 0;

  if ( (ret=stream_ethernet_init(stptr, addr, iface, ETH_P_ALL)) != 0 ){
    return ret;
  }

  struct stream_ethernet* st = (struct stream_ethernet*)*stptr;  
  
  st->base.type = PROTOCOL_ETHERNET_MULTICAST;
  st->base.FH.comment_size = 0;
  st->base.comment = NULL;

  /* callbacks */
  st->base.fill_buffer = (fill_buffer_callback)fill_buffer;
  st->base.destroy = (destroy_callback)destroy;

  return 0;
}

int stream_add(struct stream* st, const stream_addr_t* addr){
	if ( !st || stream_addr_type(addr) != STREAM_ADDR_ETHERNET ){
		return EINVAL;
	}

	if ( st->type != PROTOCOL_ETHERNET_MULTICAST ){
		return ERROR_INVALID_PROTOCOL;
	}

	struct stream_ethernet* se = (struct stream_ethernet*)st;
	return stream_ethernet_add(se, &addr->ether_addr);
}
