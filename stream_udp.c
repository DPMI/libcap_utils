#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "caputils/caputils.h"
#include <assert.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int stream_udp_init(struct stream* st, const char* address, int port){
  struct sockaddr_in sender;
  struct ifreq ifr;

  assert(st);
  assert(address);

  /* open udp socket */
  st->mySocket=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if ( st->mySocket < 0 ){
    perror("socket open failed");
    return errno;
  }

  setsockopt(st->mySocket, SOL_SOCKET, SO_REUSEADDR,(void*)1, sizeof(int));
  setsockopt(st->mySocket, SOL_SOCKET, SO_BROADCAST, (void*)1, sizeof(int));

  sender.sin_family = AF_INET;
  inet_aton(address, &sender.sin_addr);
  sender.sin_port = htons(port);

  if( bind (st->mySocket, (struct sockaddr *) &sender, sizeof(sender)) < 0 ){
    perror("Cannot bind port number");
    return errno;
  }

#ifdef DEBUG
  printf("UDP Multi/uni-cast\nIP.destination=%s UDP.port=%d\n", address,port);
#endif
  st->address = strdup(address);

  /* query interface index */
  if ( ioctl(st->mySocket, SIOCGIFINDEX, &ifr) == -1 ){
    perror("SIOCGIFINDEX error");
    return errno;
  }
  st->ifindex=ifr.ifr_ifindex;

  /* query default MTU */
  if(ioctl(st->mySocket,SIOCGIFMTU,&ifr) == -1 ) {
    perror("SIOCGIIFMTU");
    return errno;
  }
  st->if_mtu=ifr.ifr_mtu;

  return 0;
}
