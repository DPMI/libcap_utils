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
#include <pfring.h>
#include <pcap/pcap.h>
#include <pcap/bpf.h>

#define MAX_ADDRESS 100

struct stream_pfring {
  struct stream base;
  pfring* pd;
  int port;
  int if_mtu;
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
static int match_ma_pkt(const struct stream_pfring* st, const struct ethhdr* ethhdr){
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

static int read_packet(struct stream_pfring* st, struct timeval* timeout){
	assert(st);

	do {
		struct pfring_pkthdr hdr;
		while ( pfring_recv(st->pd, (u_char**)&st->frame[st->base.writePos], 0, &hdr, 1) == 0 ) {
		}

		char* dst = st->frame[st->base.writePos];

		/* Setup pointers */
		const struct ethhdr* eh = (const struct ethhdr*)dst;
		const struct sendhead* sh = (const struct sendhead*)(dst + sizeof(struct ethhdr));

		/* Check if it is a valid packet and if it was destinationed here */
		int match;
		if ( (match=match_ma_pkt(st, eh)) == -1 ){
			fprintf(stderr, "throwing away because no matching address\n");
			continue;
		}

#ifdef DEBUG
		// fprintf(stderr, "got measurement frame with %d capture packets [BU: %3.2f%%]\n", ntohl(sh->nopkts), 0.0f);
		//printf("write: %d read %d\n", st->base.writePos, st->base.readPos);
#endif

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

int stream_pfring_read(struct stream_pfring* st, cap_head** header, const struct filter* filter, struct timeval* timeout){
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
		read_packet(st, timeout);
	}

	/* no packets available */
	if ( st->num_packets == 0 ){
		return EAGAIN;
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
		fprintf(stderr, "caplen 0\n");
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

long stream_pfring_add(struct stream* stt, const struct ether_addr* addr){
	struct stream_pfring* st= (struct stream_pfring*)stt;

	if ( st->num_address == MAX_ADDRESS ){
		return EBUSY;
	}

  /* parse hwaddr from user */
  if ( (addr->ether_addr_octet[0] & 0x01) == 0 ){
    return ERROR_INVALID_HWADDR_MULTICAST;
  }

  /* store parsed address */
  memcpy(&st->address[st->num_address], addr, ETH_ALEN);
  st->num_address++;

  return 0;
}

static long destroy(struct stream_pfring* st){
  free(st->base.comment);
  free(st);
  return 0;
}

long stream_pfring_create(struct stream** stptr, const struct ether_addr* addr, const char* iface, const char* mpid, const char* comment, int flags){
  fprintf(stderr, "pf_ring is not supported for output streams\n");
  return EINVAL;
}

long stream_pfring_open(struct stream** stptr, const struct ether_addr* addr, const char* iface, size_t buffer_size){
  int ret = 0;
  assert(stptr);

  /* validate arguments */
  if ( !(addr && iface) ){
    return EINVAL;
  }

  pfring_config(99);

  /* open pfring */
  char* derp = strdup(iface);
  pfring* pd = pfring_open(derp, 1, 9000, 0);
  if ( !pd ){
	  return errno;
  }

  pfring_set_application_name(pd, "libcap_utils");

  uint32_t version;
  pfring_version(pd, &version);
  fprintf(stderr, "Using PF_RING v.%d.%d.%d\n",
          (version & 0xFFFF0000) >> 16,
          (version & 0x0000FF00) >> 8,
          version & 0x000000FF);

/*u_char mac_address[6] = { 0 };

  if(pfring_get_bound_device_address(pd, mac_address) != 0)
    fprintf(stderr, "Impossible to know the device address\n");
  else
    printf("Capturing from %s [%s]\n", iface, etheraddr_string(mac_address, buf));
*/
  printf("# Device RX channels: %d\n", pfring_get_num_rx_channels(pd));

  if((ret = pfring_set_direction(pd, rx_and_tx_direction)) != 0)
    ; //fprintf(stderr, "pfring_set_direction returned %d (perhaps you use a direction other than rx only with DNA ?)\n", ret);

  if((ret = pfring_set_socket_mode(pd, recv_only_mode)) != 0)
    fprintf(stderr, "pfring_set_socket_mode returned [rc=%d]\n", ret);


  char bpfFilter[] = "ether proto 0x810";
  ret = pfring_set_bpf_filter(pd, bpfFilter);
  if(ret != 0)
	  printf("pfring_set_bpf_filter(%s) returned %d\n", bpfFilter, ret);
  else
	  printf("Successfully set BPF filter '%s'\n", bpfFilter);

  int if_mtu = 9000;

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
  if ( (ret = stream_alloc(stptr, PROTOCOL_ETHERNET_MULTICAST, sizeof(struct stream_pfring), buffer_size) != 0) ){
    return ret;
  }
  struct stream_pfring* st = (struct stream_pfring*)*stptr;
  st->pd = pd;
  st->num_address = 0;
  st->if_mtu = if_mtu;
  memset(st->seqnum, 0, sizeof(long unsigned int) * MAX_ADDRESS);

  if (pfring_enable_ring(pd) != 0) {
    printf("Unable to enable ring :-(\n");
    pfring_close(pd);
    return(-1);
  }

  /* setup buffer pointers (see brief overview at struct declaration) */
  st->num_frames = frames;
  st->num_packets = 0;
  st->read_ptr = NULL;
  st->base.readPos = 0;
  st->base.writePos = 0;
  for ( unsigned int i = 0; i < frames; i++ ){
	  st->frame[i] = st->base.buffer + frame_offset + i * if_mtu;
  }

  /* add membership to group */
  if ( (ret=stream_pfring_add(&st->base, addr)) != 0 ){
	  return ret;
  }

/*
  if ( (ret=stream_pfring_init(stptr, addr, iface, ETH_P_ALL, buffer_size)) != 0 ){
    return ret;
  }
*/
  st->base.type = PROTOCOL_ETHERNET_MULTICAST;
  st->base.FH.comment_size = 0;
  st->base.comment = NULL;

  /* callbacks */
  st->base.fill_buffer = NULL;
  st->base.destroy = (destroy_callback)destroy;
  st->base.write = NULL;
  st->base.read = (read_callback)stream_pfring_read;

  return 0;
}

/* I CAN HAZ PASTA PLOX? */
int pcap_compile_nopcap(int snaplen_arg, int linktype_arg,
                        struct bpf_program *program,
                        const char *buf, int optimize, bpf_u_int32 mask)
{
	pcap_t *p;
	int ret;

	p = pcap_open_dead(linktype_arg, snaplen_arg);
	if (p == NULL)
		return (-1);
	ret = pcap_compile(p, program, buf, optimize, mask);
	if ( ret != 0 ){
		fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(p));
	}
	pcap_close(p);
	return (ret);
}

/*
static int stream_add(struct stream* st, const stream_addr_t* addr){
	if ( !st || stream_addr_type(addr) != STREAM_ADDR_ETHERNET ){
		return EINVAL;
	}

	if ( st->type != PROTOCOL_ETHERNET_MULTICAST ){
		return ERROR_INVALID_PROTOCOL;
	}

	struct stream_pfring* se = (struct stream_pfring*)st;
	return stream_pfring_add(se, &addr->ether_addr);
}
*/
