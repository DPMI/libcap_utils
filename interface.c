#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "caputils/interface.h"
#include "caputils/caputils.h"
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

int iface_get(const char* name, struct iface* iface){
  struct ifreq ifr;

  /* store the iface name */
  strncpy(ifr.ifr_name,   name, IFNAMSIZ);
  strncpy(iface->if_name, name, IFNAMSIZ);

  /* open raw socket */
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if ( fd < 0 ){
    return errno;
  }

  /* get iface index */
  if ( ioctl(fd, SIOCGIFINDEX, &ifr) == -1 ){
    return errno;
  }
  iface->if_index = ifr.ifr_ifindex;

  /* get iface MTU */
  if ( ioctl(fd, SIOCGIFMTU, &ifr) == -1 ){
    return errno;
  }
  iface->if_mtu = ifr.ifr_mtu;

  /* query interface flags */
  if ( ioctl(fd, SIOCGIFFLAGS, &ifr) == -1 ){
    return errno;
  }
  iface->if_up        = ifr.ifr_flags & IFF_UP;
  iface->if_loopback  = ifr.ifr_flags & IFF_LOOPBACK;
  iface->if_multicast = ifr.ifr_flags & IFF_MULTICAST;

  return 0;
}
