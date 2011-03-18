#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "caputils/caputils.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <arpa/inet.h>

static int fill_buffer(struct stream* st, size_t len){
  char osrBuffer[buffLen] = {0,};
  int readBytes;

  char* ether = osrBuffer;
  struct ethhdr *eh=(struct ethhdr *)ether;
  struct sendhead *sh=(struct sendhead *)(ether+sizeof(struct ethhdr));
  
  while ( st->bufferSize==0 ){ // Read one chunk of data, mostly to determine sequence number and stream version. 
    readBytes=recvfrom(st->mySocket, osrBuffer, len, 0, NULL, NULL);

#ifdef DEBUG
    printf("eth.type=%04x %02X:%02X:%02X:%02X:%02X:%02X --> %02X:%02X:%02X:%02X:%02X:%02X",ntohs(eh->h_proto),eh->h_source[0],eh->h_source[1],eh->h_source[2],eh->h_source[3],eh->h_source[4],eh->h_source[5],eh->h_dest[0],eh->h_dest[1],eh->h_dest[2],eh->h_dest[3],eh->h_dest[4],eh->h_dest[5]);
    printf("st->address = %02x:%02x:%02x:%02x:%02x:%02x \n",st->address[0],st->address[1],st->address[2],st->address[3],st->address[4],st->address[5]);
#endif
	
    /* terminated */
    if ( readBytes < 0 ){
      perror("Cannot receive Ethernet data.");
      return 0;
    }

    /* proper shutdown */
    if( readBytes==0 ){
      perror("Connection closed by client.");
      return 0;
    }

    /* check protocol and destination */
    if( ntohs(eh->h_proto) != LLPROTO || memcmp((const void*)eh->h_dest,(const void*)st->address, ETH_ALEN) != 0 ){
      continue;
    }

    /* increase packet count */
    st->pktCount += ntohs(sh->nopkts);

    /* if no sequencenr is set some additional checks are made.
     * they will also run when the sequence number wraps, but that ok since the
     * sequence number will match in that case anyway. */
    if ( st->expSeqnr == 0 ){
      st->expSeqnr = ntohl(sh->sequencenr);

      /* read stream version */
      st->FH.version.major=ntohs(sh->version.major);
      st->FH.version.minor=ntohs(sh->version.minor);

      /* ensure we can read this version */
      if ( !is_valid_version(&st->FH) ){
	return -1;
      }
    }

    /* validate sequence number */
    if( st->expSeqnr != ntohl(sh->sequencenr) ){
      fprintf(stderr,"Missmatch of sequence numbers. Expeced %ld got %d\n",st->expSeqnr, ntohl(sh->sequencenr));
      st->expSeqnr = ntohl(sh->sequencenr); /* reset sequence number */
    }

    /* increment sequence number (next packet is expected to have +1) */
    st->expSeqnr++;

    /* wrap sequence number */
    if( st->expSeqnr>=0xFFFF ){
      st->expSeqnr=0;
    }

    /* copy packets to stream buffer */
    size_t header_size = sizeof(struct ethhdr)+sizeof(struct sendhead);
    memcpy(st->buffer + st->bufferSize, osrBuffer + header_size, readBytes - header_size);
    st->bufferSize += readBytes - header_size;

#ifdef DEBUG
    printf("Packet contained %d bytes (Eth %d, Send %d, Cap %d) Buffer Size = %d / %d  Pkts %ld \n",readBytes,sizeof(struct ethhdr), sizeof(struct sendhead),sizeof(struct cap_header),st->bufferSize, buffLen, st->pktCount);
#endif

    /* This indicates a flush from the sender.. */
    if( ntohs(sh->flush) == 1 ){
      printf("Sender terminated. \n");
      st->flushed=1;
      break;//Break the while loop.
    }
  }

  return readBytes;
}

int stream_ethernet_init(struct stream* st, const char* address, const char* iface){
  struct ifreq ifr;
  struct packet_mreq mcast;
  struct sockaddr_ll sll;

  assert(st);
  assert(address);
  assert(nic);

  /* store the iface name */
  strncpy(ifr.ifr_name, iface, IFNAMSIZ);

  /* open raw socket */
  st->mySocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));//LLPROTO));
  if ( st->mySocket < 0 ){
    perror("socket open failed");
    return errno;
  }

  if ( ioctl(st->mySocket, SIOCGIFINDEX, &ifr) == -1 ){
    perror("SIOCGIFINDEX failed");
    return errno;
  }
  st->ifindex = ifr.ifr_ifindex;

  if ( ioctl(st->mySocket, SIOCGIFMTU, &ifr) == -1 ){
    perror("SIOCGIFMTU failed");
    return errno;
  }
  st->if_mtu = ifr.ifr_mtu;

  char* myaddress = (char*)malloc(strlen(address)+1); /* stream takes ownership of memory */
  eth_aton(myaddress, address);
  mcast.mr_ifindex = st->ifindex;
  mcast.mr_type = PACKET_MR_MULTICAST;
  mcast.mr_alen = ETH_ALEN;
  memcpy(mcast.mr_address, myaddress, ETH_ALEN);

  if ( setsockopt(st->mySocket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void*)&mcast,sizeof(mcast)) == -1 ){
    perror("Adding multicast address failed");
    free(myaddress);
    return errno;
  }

  sll.sll_family=AF_PACKET;
  sll.sll_ifindex=st->ifindex;
  sll.sll_protocol=htons(ETH_P_ALL);//LLPROTO);
  sll.sll_pkttype=PACKET_MULTICAST;
  memcpy(sll.sll_addr,myaddress,ETH_ALEN);

  if ( bind(st->mySocket, (struct sockaddr *) &sll, sizeof(sll)) == -1 ) {
    perror("Binding to interface.");
    free(myaddress);
    return errno;
  }
  
#ifdef DEBUG
  printf("Ethernet Multicast\nEthernet.type=%04X\nEthernet.dst=%02X:%02X:%02X:%02X:%02X:%02X\nInterface=%s (%d)\n", LLPROTO
	 ,mcast.mr_address[0], mcast.mr_address[1], mcast.mr_address[2]
	 ,mcast.mr_address[3], mcast.mr_address[4], mcast.mr_address[5]
	 ,nic, mcast.mr_ifindex);
#endif
  
  st->address = myaddress; /* take ownership of memory */
  st->FH.comment_size=0;
  st->comment=0;

  /* callbacks */
  st->fill_buffer = fill_buffer;
  st->destroy = NULL;

  return 0;
}
