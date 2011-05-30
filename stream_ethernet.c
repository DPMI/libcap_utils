#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "caputils/caputils.h"
#include "caputils_int.h"
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

static char osrBuffer[buffLen] = {0,};

struct stream_ethernet {
  struct stream base;
  int socket;
  int port;
  int if_index;
  int if_mtu;
  struct sockaddr_ll sll;
  struct ether_addr address;
};

static int fill_buffer(struct stream_ethernet* st, struct timeval* timeout){
  int readBytes;

  size_t available = buffLen;

  const char* ether = osrBuffer;
  const struct ethhdr *eh=(const struct ethhdr *)ether;
  const struct sendhead *sh=(const struct sendhead *)(ether + sizeof(struct ethhdr));

  /* copy old content */
  if ( st->base.readPos > 0 ){
    size_t bytes = st->base.bufferSize - st->base.readPos;
    memmove(st->base.buffer, st->base.buffer + st->base.readPos, bytes); /* move content */
    memset(st->base.buffer + bytes, 0, buffLen-bytes); /* reset rest */
    st->base.bufferSize = bytes;
    st->base.readPos = 0;
    available = buffLen - bytes;
  }

  while ( 1 ){
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(st->socket, &fds);
    
    switch ( select(st->socket+1, &fds, NULL, NULL, timeout) ){
    case -1:
      return errno;
    case 0:
      errno = EAGAIN;
      return -1;
    case 1:
      break;
    }

    readBytes=recvfrom(st->socket, osrBuffer, available, 0, NULL, NULL);

#ifdef DEBUG
    printf("eth.type=%04x\n", ntohs(eh->h_proto));
    printf("\t%02X:%02X:%02X:%02X:%02X:%02X --> %02X:%02X:%02X:%02X:%02X:%02X\n",
	   eh->h_source[0],
	   eh->h_source[1],
	   eh->h_source[2],
	   eh->h_source[3],
	   eh->h_source[4],
	   eh->h_source[5],
	   eh->h_dest[0],
	   eh->h_dest[1],
	   eh->h_dest[2],
	   eh->h_dest[3],
	   eh->h_dest[4],
	   eh->h_dest[5]);
    printf("\tst->address = %02x:%02x:%02x:%02x:%02x:%02x\n",
	   st->address.ether_addr_octet[0],
	   st->address.ether_addr_octet[1],
	   st->address.ether_addr_octet[2],
	   st->address.ether_addr_octet[3],
	   st->address.ether_addr_octet[4],
	   st->address.ether_addr_octet[5]);
#endif
	
    /* terminated */
    if ( readBytes < 0 ){
      perror("Cannot receive Ethernet data.");
      return -1;
    }

    /* proper shutdown */
    if( readBytes==0 ){
      perror("Connection closed by client.");
      return -1; /* return -1 so it won't try again */
    }

    /* check protocol and destination */
    int match_proto = ntohs(eh->h_proto) == LLPROTO;
    int match_addr = memcmp((const void*)eh->h_dest, st->address.ether_addr_octet, ETH_ALEN) == 0;
    if( !(match_proto && match_addr) ){
#ifdef DEBUG
      printf("\tskipping (proto: %d, addr: %d)\n", match_proto, match_addr);
#endif /* DEBUG */
      continue;
    }

    /* increase packet count */
    st->base.pktCount += ntohs(sh->nopkts);

    /* if no sequencenr is set some additional checks are made.
     * they will also run when the sequence number wraps, but that ok since the
     * sequence number will match in that case anyway. */
    if ( st->base.expSeqnr == 0 ){
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
      st->base.expSeqnr = ntohl(sh->sequencenr);
    }

    match_inc_seqnr(&st->base, sh);

    /* copy packets to stream buffer */
    size_t header_size = sizeof(struct ethhdr)+sizeof(struct sendhead);
    memcpy(st->base.buffer + st->base.bufferSize, osrBuffer + header_size, readBytes - header_size);
    st->base.bufferSize += readBytes - header_size;

#ifdef DEBUG
    printf("Packet contained %d bytes (Eth %zd, Send %zd, Cap %zd) Buffer Size = %d / %d  Pkts %ld \n",readBytes,sizeof(struct ethhdr), sizeof(struct sendhead),sizeof(struct cap_header),st->base.bufferSize, buffLen, st->base.pktCount);
#endif

    /* This indicates a flush from the sender.. */
    if( ntohs(sh->flush) == 1 ){
      printf("Sender terminated. \n");
      st->base.flushed=1;
    }

    break; //Break the while loop.
  }

  return readBytes;
}

long stream_write(struct stream_ethernet* st, u_char* data, size_t size){
  if ( sendto(st->socket, data, size, 0, (struct sockaddr*)&st->sll, sizeof(st->sll)) < 0 ){
    return errno;
  }
  return 0;
}

long stream_ethernet_init(struct stream** stptr, const char* address, const char* iface, uint16_t proto){
  struct ifreq ifr;
  struct packet_mreq mcast = {0,};

  long ret = 0;
  
  assert(stptr);

  /* validate arguments */
  if ( !(address && iface) ){
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

  /* parse hwaddr from user */
  struct ether_addr* myaddress = ether_aton(address);
  if ( !myaddress ){
    return ERROR_INVALID_HWADDR;
  }
  
  /* store parsed address */
  memcpy(&st->address, myaddress, ETH_ALEN);

  /* setup multicast address */
  mcast.mr_ifindex = st->if_index;
  mcast.mr_type = PACKET_MR_MULTICAST;
  mcast.mr_alen = ETH_ALEN;
  memcpy(mcast.mr_address, myaddress, ETH_ALEN);

  /* setup ethernet multicast */
  if ( setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void*)&mcast, sizeof(mcast)) == -1 ){
    perror("Adding multicast address failed");
    return errno;
  }

  memset(&st->sll, 0, sizeof(st->sll));
  st->sll.sll_family=AF_PACKET;
  st->sll.sll_ifindex=st->if_index;
  st->sll.sll_protocol=htons(proto);
  st->sll.sll_pkttype=PACKET_MULTICAST;
  memcpy(st->sll.sll_addr, myaddress,ETH_ALEN);

  if ( bind(fd, (struct sockaddr *) &st->sll, sizeof(st->sll)) == -1 ) {
    perror("Binding to interface.");
    return errno;
  }
  
#ifdef DEBUG
  printf("Ethernet Multicast\nEthernet.type=%04X\nEthernet.dst=%02X:%02X:%02X:%02X:%02X:%02X\nInterface=%s (%d)\n", LLPROTO
	 ,mcast.mr_address[0], mcast.mr_address[1], mcast.mr_address[2]
	 ,mcast.mr_address[3], mcast.mr_address[4], mcast.mr_address[5]
	 ,iface, mcast.mr_ifindex);
#endif

  return 0;
}

long destroy(struct stream_ethernet* st){
  free(st->base.comment);
  free(st);
  return 0;
}

long stream_ethernet_create(struct stream** stptr, const char* address, const char* iface, const char* mpid, const char* comment){
  long ret = 0;

  if ( (ret=stream_ethernet_init(stptr, address, iface, LLPROTO)) != 0 ){
    return ret;
  }

  struct stream_ethernet* st = (struct stream_ethernet*)*stptr;  

  st->base.FH.comment_size = strlen(comment);
  st->base.comment = strdup(comment);

  /* callbacks */
  st->base.fill_buffer = (fill_buffer_callback)fill_buffer;
  st->base.destroy = (destroy_callback)destroy;
  st->base.write = (write_callback)stream_write;

  return 0;
}

long stream_ethernet_open(struct stream** stptr, const char* address, const char* iface){
  long ret = 0;

  if ( (ret=stream_ethernet_init(stptr, address, iface, ETH_P_ALL)) != 0 ){
    return ret;
  }

  struct stream_ethernet* st = (struct stream_ethernet*)*stptr;  
  
  st->base.FH.comment_size = 0;
  st->base.comment = NULL;

  /* callbacks */
  st->base.fill_buffer = (fill_buffer_callback)fill_buffer;
  st->base.destroy = (destroy_callback)destroy;

  return 0;
}
