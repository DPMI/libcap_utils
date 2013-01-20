#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "caputils/caputils.h"
#include "caputils/interface.h"
#include "caputils_int.h"
#include "stream.h"
#include "stream_buffer.h"
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MAX_ADDRESS 100

struct stream_udp {
	struct stream base;
	int socket;
	int if_index;
	struct in_addr address[MAX_ADDRESS];
	unsigned int seqnum[MAX_ADDRESS];

	struct stream_frame_buffer fb;
	char* frame[0];
};

static int __attribute__((pure)) is_multicast(struct in_addr addr){
	const uint32_t   mask = htonl(0xf0000000);
	const uint32_t prefix = htonl(0xe0000000);
	return (addr.s_addr & mask) == prefix;
}

/**
 * Test if a MA packet is valid and matches our expected destinations
 * Returns the matching address index or -1 for invalid packets.
 */
static int match_ma_pkt(const struct stream_udp* st, const struct in_addr src){
	for ( unsigned int i = 0; i < st->base.num_addresses; i++ ){
		if ( src.s_addr == st->address[i].s_addr ) return i;
	}

	return -1; /* ethernet stream did not match any of our expected */
}

static int stream_udp_read(struct stream_udp* st, cap_head** cp, struct filter* filter, struct timeval* timeout){
	return stream_frame_buffer_read(&st->base, &st->fb, cp, filter, timeout);
}

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

static int stream_udp_read_frame(struct stream_udp* st, char* dst, struct timeval* timeout){
  assert(st);

  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(st->socket, &fds);

  if ( select(st->socket+1, &fds, NULL, NULL, timeout) != 1 ){
	  errno = EAGAIN;
	  return 0;
  }

  struct sockaddr_in src;
  socklen_t addrlen = sizeof(struct sockaddr_in);
  ssize_t bytes = recvfrom(st->socket, dst, st->base.if_mtu, 0, &src, &addrlen);
  if ( bytes < 0 ){ /* error occurred */
	  perror("Cannot receive UDP data.");
	  return 0;
  } else if ( bytes == 0 ){ /* proper shutdown */
	  perror("Connection closed by client.");
	  return 0;
  }

  /* Check if it is a valid packet and if it was destinationed here */
  int match;
  if ( (match=match_ma_pkt(st, src.sin_addr)) == -1 ){
	  return EAGAIN;
  }

#ifdef DEBUG
  fprintf(stderr, "got measurement frame with %d capture packets [BU: %3.2f%%]\n", ntohl(sh->nopkts), 0.0f);
#endif

  return 1;
}

int stream_udp_add(stream_t stt, const struct in_addr addr){
	struct stream_udp* st = (struct stream_udp*)stt;

	if ( st->base.num_addresses == MAX_ADDRESS ){
		return EBUSY;
	}

  /* parse hwaddr from user */
	if ( !is_multicast(addr) ){
    return ERROR_INVALID_MULTICAST;
  }

  /* store parsed address */
	st->address[st->base.num_addresses] = addr;

  /* setup multicast address */
	struct ip_mreqn mcast;
	mcast.imr_multiaddr = addr;
	mcast.imr_address.s_addr = htonl(INADDR_ANY);
  mcast.imr_ifindex = st->if_index;

#ifdef DEBUG
  fprintf(stderr, "Adding membership to IP multicast group %s.\n", inet_ntoa(addr));
#endif

  if ( setsockopt(st->socket, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mcast, sizeof(struct ip_mreqn)) == -1 ){
	  printf("asdf\n");
	  return errno;
  }

  st->base.num_addresses++;
  return 0;

}

static int stream_udp_init(stream_t* stptr, size_t mtu){
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

  const size_t num_frames = 250;
  const size_t buffer_size = stream_frame_buffer_size(num_frames, mtu);

  /* Initialize the structure */
  if ( (ret = stream_alloc(stptr, PROTOCOL_UDP_MULTICAST, sizeof(struct stream_udp), buffer_size, mtu) != 0) ){
    return ret;
  }
  struct stream_udp* st = (struct stream_udp*)*stptr;
  stream_frame_init(&st->fb, (read_frame_callback)stream_udp_read_frame, (char*)st->frame, num_frames, mtu);

  st->socket = fd;
  st->if_index = 0;
  st->base.if_mtu = mtu;
  memset(st->seqnum, 0, sizeof(unsigned int) * MAX_ADDRESS);

  return 0;
}

static int stream_udp_destroy(struct stream_udp* st){
	shutdown(st->socket, SHUT_RDWR);
	close(st->socket);
	free(st);
	return 0;
}

static size_t estimate_mtu(struct sockaddr_in addr, const char* iface){
	if ( iface ){
		struct iface ifstat;
		int ret;
		if ( (ret=iface_get(iface, &ifstat)) != 0 ){
			errno = ret;
			goto error;
		}
		return ifstat.if_mtu;
	} else {
		int mtu;
		socklen_t optlen = sizeof(int);
		int fd = socket(AF_INET, SOCK_DGRAM, 0);
		if ( !fd ) goto error;
		if ( connect(fd, &addr, sizeof(struct sockaddr_in)) == -1 ) goto error;
		if ( getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &optlen) == -1 ) goto error;
		close(fd);
		return mtu;
	}
  error:
	fprintf(stderr, "failed to estimate MTU, defaulting to 1500: %s\n", strerror(errno));
	return 1500;
}

int stream_udp_create(struct stream** stptr, const struct sockaddr_in* addr, const char* iface, int flags){
  int ret = 0;
  size_t mtu = estimate_mtu(*addr, iface);
  if ( (ret=stream_udp_init(stptr, mtu)) != 0 ){
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

int stream_udp_open(stream_t* stptr, const struct sockaddr_in* addr, const char* iface){
  int ret = 0;

  /* multicasting requires a known interface to get properties */
  if ( is_multicast(addr->sin_addr) && !iface ){
	  fprintf(stderr, "Multicasting requires to set an interface with -i\n");
	  return EINVAL;
  }

  const size_t mtu = estimate_mtu(*addr, iface);

  if ( (ret=stream_udp_init(stptr, mtu)) != 0 ){
    return ret;
  }

  struct stream_udp* st = (struct stream_udp*)*stptr;
  st->if_index = 0;
  st->base.if_mtu = mtu;

  struct sockaddr_in src;
  src.sin_family = AF_INET;
  src.sin_addr.s_addr = is_multicast(addr->sin_addr) ? htonl(INADDR_ANY) : addr->sin_addr.s_addr;
  src.sin_port = addr->sin_port;

  /* bind listen address */
  if ( (ret=bind(st->socket, &src, sizeof(struct sockaddr_in))) != 0 ){
	  free(st);
	  return ret;
  }

	/* for multicast setup, add primary address */
  if ( is_multicast(addr->sin_addr) ){
	  if ( (ret=stream_udp_add(&st->base, addr->sin_addr)) != 0 ){
		  return ret;
	  }
  }

  /* callbacks */
  st->base.destroy = (destroy_callback)stream_udp_destroy;
  st->base.read = (read_callback)stream_udp_read;

  return 0;
}
