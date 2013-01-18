#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "caputils/caputils.h"
#include "caputils_int.h"
#include "stream.h"
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

struct stream_udp {
	struct stream base;
	int socket;
	struct sockaddr_in addr;
};

static int stream_udp_write(struct stream_udp* st, const void* data, size_t size){
	if ( size > st->base.if_mtu ){
		fprintf(stderr, "packet is larger (%zd) than MTU (%zd), ignoring\n", size, st->base.if_mtu);
		return EINVAL;
	}
  if ( send(st->socket, data, size, 0) < 0 ){
    return errno;
  }
  return 0;
}

static int stream_udp_init(stream_t* stptr, const struct sockaddr_in* addr){
  int ret;
  assert(st);
  assert(addr);

  /* open udp socket */
  int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if ( fd < 0 ){
    return errno;
  }

  int on = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
  setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(int));

  /* query default MTU */
  /* if(ioctl(fd, SIOCGIFMTU, &ifr) == -1 ) { */
  /*   return errno; */
  /* } */
  const size_t mtu = 1500; //ifr.ifr_mtu;

  /* Initialize the structure */
  if ( (ret = stream_alloc(stptr, PROTOCOL_UDP_MULTICAST, sizeof(struct stream_udp), 0, mtu) != 0) ){
    return ret;
  }
  struct stream_udp* st = (struct stream_udp*)*stptr;
  st->socket = fd;
  st->addr = *addr;
  st->base.if_mtu = mtu;

  return 0;
}

static int stream_udp_destroy(struct stream_udp* st){
	shutdown(st->socket, SHUT_RDWR);
	close(st->socket);
	free(st);
	return 0;
}

int stream_udp_create(struct stream** stptr, const struct sockaddr_in* addr, int flags){
  int ret = 0;

  if ( (ret=stream_udp_init(stptr, addr)) != 0 ){
    return ret;
  }

  struct stream_udp* st = (struct stream_udp*)*stptr;

  /* connect to host */
  struct sockaddr_in dst = *addr;
  if ( (ret=connect(st->socket, &dst, sizeof(struct sockaddr_in))) != 0 ){
	  free(st);
	  return ret;
  }

  /* callbacks */
  st->base.destroy = (destroy_callback)stream_udp_destroy;
  st->base.write = (write_callback)stream_udp_write;

  return 0;
}
