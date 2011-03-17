#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include "cap_utils.h"

int stream_ethernet_init(struct stream* st, const char* address){
  struct ifreq ifr;
  struct packet_mreq mcast;
  struct sockaddr_ll sll;

  assert(st);
  assert(address);

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

  return 0;
}
