#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <caputils/caputils.h>
#include "caputils_int.h"
#include "stream.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>

int stream_alloc(struct stream** stptr, enum protocol_t protocol, size_t size){
	assert(stptr);

	/* the buffer is always placed after the struct */
	struct stream* st = (struct stream*)malloc(size + buffLen);
	*stptr = st;

	st->type = protocol;
	st->comment = NULL;
	st->buffer = (char*)st + size; /* calculate pointer to buffer */

	st->expSeqnr = 0;
	st->bufferSize=0;
	st->readPos=0;
	st->flushed = 0;
	st->stat.recv = 0;
	st->stat.matched = 0;

	/* callbacks */
	st->fill_buffer = NULL;
	st->destroy = NULL;

	memset(st->buffer, 0, buffLen);

	/* initialize file_header */
	st->FH.comment_size = 0;
	memset(st->FH.mpid, 0, 200); /* @bug what is 200? why is not [0] = 0 enought? */

	return 0;
}

void match_inc_seqnr(long unsigned int* restrict seq, const struct sendhead* restrict sh){
	/* validate sequence number */
	if( *seq != ntohl(sh->sequencenr) ){
		fprintf(stderr,"Missmatch of sequence numbers. Expeced %ld got %d\n", *seq, ntohl(sh->sequencenr));
		*seq = ntohl(sh->sequencenr); /* reset sequence number */
	}

	/* increment sequence number (next packet is expected to have +1) */
	(*seq)++;

	/* wrap sequence number */
	if( *seq >= 0xFFFF ){
		*seq = 0;
	}
}

void stream_get_version(const struct stream* st, struct file_version* dst){
	dst->major = st->FH.version.major;
	dst->minor = st->FH.version.minor;
}

const char* stream_get_comment(const struct stream* st){
	return st->comment;
}

const char* stream_get_mampid(const struct stream* st){
	return st->FH.mpid;
}

const struct stream_stat* stream_get_stat(const struct stream* st){
	return &st->stat;
}

/**
 * Validates the file_header version against libcap_utils version. Prints
 * warning to stderr if version mismatch.
 * @return Non-zero if version is valid.
 */
int is_valid_version(struct file_header_t* fhptr){
	if( fhptr->version.major <= VERSION_MAJOR && fhptr->version.minor <= VERSION_MINOR ) {
		return 1;
	}

	fprintf(stderr,"Stream uses version %d.%d, this application uses ", fhptr->version.major, fhptr->version.minor);
	fprintf(stderr,"Libcap_utils version " VERSION "\n");
	fprintf(stderr,"Change libcap version or convert file.\n");
	return 0;
}

int stream_open(struct stream** stptr, const stream_addr_t* dest, const char* nic, int port){
	int ret;

	switch(stream_addr_type(dest)){
		/* case PROTOCOL_TCP_UNICAST: */
		/*   return stream_tcp_init(myStream, address, port); */

		/* case PROTOCOL_UDP_MULTICAST: */
		/*   return stream_udp_init(myStream, address, port); */

	case PROTOCOL_ETHERNET_MULTICAST:
		ret = stream_ethernet_open(stptr, &dest->ether_addr, nic);
		break;

	case PROTOCOL_LOCAL_FILE:
		ret = stream_file_open(stptr, stream_addr_have_flag(dest, STREAM_ADDR_LOCAL) ? dest->local_filename : dest->filename);
		break;

	default:
		fprintf(stderr, "Unhandled protocol %d\n", stream_addr_type(dest));
		return ERROR_NOT_IMPLEMENTED;
	}

	/** @note Only shallow copy, it might cause issues if using a local path which
	 * is referenced and freed after stream_open. Can only safely copy if open
	 * succeeded because there is no guarantee stream is allocated if it fails.  */
	if ( ret == 0 ){
		(*stptr)->addr = *dest;
	}

	return ret;
}

int stream_create(struct stream** stptr, const stream_addr_t* dest, const char* nic, const char* mpid, const char* comment){
	/* struct ifreq ifr; */
	/* int ifindex=0; */
	/* int socket_descriptor=0; */
	/* int ret; */
	/* struct sockaddr_in destination; */
	/* struct ether_addr ethernet_address; */
	const char* filename;
	int flags = stream_addr_flags(dest);

	switch ( stream_addr_type(dest) ){
	case PROTOCOL_ETHERNET_MULTICAST:
		return stream_ethernet_create(stptr, &dest->ether_addr, nic, mpid, comment, flags);

	case PROTOCOL_LOCAL_FILE:
		filename = stream_addr_have_flag(dest, STREAM_ADDR_LOCAL) ? dest->local_filename : dest->filename;
		return stream_file_create(stptr, NULL, filename, mpid, comment, flags);

	default:
		return ERROR_NOT_IMPLEMENTED;
	}


	/* switch(protocol){ */
	/*   case 3: // TCP unicast */
	/*     socket_descriptor=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); */
	/*     if(socket_descriptor<0) { */
	/* 	perror("Cannot open socket. "); */
	/* 	return(0); */
	/*     }      */
	/*     setsockopt(socket_descriptor,SOL_SOCKET,SO_REUSEADDR,(void*)1,sizeof(int)); */
	/*     destination.sin_family = AF_INET; */
	/*     destination.sin_port = htons(LISTENPORT); */
	/*     inet_aton(address,&destination.sin_addr); */
	/*     if(connect(socket_descriptor,(struct sockaddr*)&(destination),sizeof(destination))!=0){ */
	/* 	perror("Cannot connect TCP socket."); */
	/* 	return(0); */
	/*     } */
	/*     printf("Connected."); */
	/*     address=(char*)calloc(strlen(address)+1,1); */
	/*     strcpy(st->address,address);  */

	/*     break; */

	/*   case 2: // UDP multi/unicast */
	/*     socket_descriptor=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP); */
	/*     if(socket_descriptor<0) { */
	/* 	perror("Cannot open socket. "); */
	/* 	return(0); */
	/*     }      */
	/*     setsockopt(socket_descriptor,SOL_SOCKET,SO_REUSEADDR,(void*)1,sizeof(int)); */
	/*     setsockopt(socket_descriptor,SOL_SOCKET,SO_BROADCAST,(void*)1,sizeof(int)); */
	/*     destination.sin_family = AF_INET; */
	/*     inet_aton(address,&destination.sin_addr); */
	/*     destination.sin_port = htons(LISTENPORT); */
	/*     if(connect(socket_descriptor,(struct sockaddr*)&destination,sizeof(destination))!=0){ */
	/* 	perror("Cannot connect UDP socket."); */
	/* 	return(0); */
	/*     } */
	/*     address=(char*)calloc(strlen(address)+1,1); */
	/*     strcpy(st->address,address); */
	/*     break; */

	/*   case 1: // Ethernet multicast */
	/*   case 0: */
	/*   default: */
	/* }  */

	/* //  st->mySocket=socket_descriptor; */
	/* //  st->ifindex=ifindex; */

	/* return(1);   */
}

int stream_close(struct stream* st){
	return st->destroy ? st->destroy(st) : 0;

	/* ret */
	/* errno=0; */
	/* switch(myStream->type){ */
	/*   case 3://TCP */
	/*   case 2://UDP */
	/*   case 1://Ethernet */
	/*     if(close(myStream->mySocket)==-1){ */
	/* 	perror("Close failed."); */
	/* 	return(0); */
	/*     } */
	/*     break; */
	/*   case 0: */
	/*   default: */
	/*     if(fclose(myStream->myFile)==EOF){ */
	/* 	perror("Close failed."); */
	/* 	return(0); */
	/*     } */
	/*     break; */
	/* } */

	/* free(myStream->address); */
	/* free(myStream->comment); */
	/* free(myStream->filename); */

	/* return(1); */
}

int stream_write(struct stream *outStream, const void* data, size_t size){
	assert(outStream);
	assert(outStream->write);
	return outStream->write(outStream, data, size);
}

static int fill_buffer(struct stream* st, struct timeval* timeout){
	if( st->flushed==1 ){
		return -1;
	}

	int ret;

	switch(st->type){
	case PROTOCOL_TCP_UNICAST://TCP
	case PROTOCOL_UDP_MULTICAST://UDP
		fprintf(stderr, "Not reimplemented\n");
		abort();
		break;
	case PROTOCOL_ETHERNET_MULTICAST://ETHERNET
	case PROTOCOL_LOCAL_FILE:
		ret = st->fill_buffer(st, timeout);
		if ( ret > 0 ){ /* common case */
			return 0;
		} else if ( ret < 0 ){ /* failed to read */
			return errno;
		} else if ( ret == 0 ){ /* EOF, TCP shutdown etc */
			return -1;
		}
		break;
	}

	/* not reached */
	return 0;
}

int stream_read(struct stream *myStream, cap_head** data, const struct filter *my_Filter, struct timeval* timeout){
	int filterStatus=0;
	int skip_counter=-1;
	int ret = 0;

	/* as a precaution, reset the datapoint to NULL so errors will be easier to track down */
	*data = NULL;

	do {
		skip_counter++;

		/* bufferSize tells how much data there is available in the buffer */
		if( myStream->bufferSize - myStream->readPos < sizeof(struct cap_header) ){
			if ( (ret=fill_buffer(myStream, timeout)) != 0 ){
				return ret; /* could not read */
			}
			continue;
		}

		// We have some data in the buffer.
		struct cap_header* cp = (struct cap_header*)(myStream->buffer + myStream->readPos);
		const size_t packet_size = sizeof(struct cap_header) + cp->caplen;
		const size_t start_pos = myStream->readPos;
		const size_t end_pos = start_pos + packet_size;

		if ( cp->caplen == 0 ){
			return ERROR_CAPFILE_INVALID;
		}

		assert(packet_size > 0);

		if( end_pos > myStream->bufferSize ) {
			if ( (ret=fill_buffer(myStream, timeout)) != 0 ){
				return ret; /* could not read */
			}

			continue;
		}

		/* set next packet and advance the read pointer */
		*data = cp;
		myStream->readPos += packet_size;
		myStream->stat.read++;

		filterStatus = 1; /* match by default, i.e. if no filter is used. */
		if ( my_Filter ){
			filterStatus = filter_match(my_Filter, cp->payload, cp);
		}
	} while(filterStatus==0);

	myStream->stat.matched++;
	return 0;
}

static const char* type[4] = {"file", "ethernet", "udp", "tcp"};
int stream_from_getopt(struct stream** st, char* argv[], int optind, int argc, const char* iface, const char* program_name){
	int ret;
	stream_addr_t addr;
	memset(&addr, sizeof(stream_addr_t), 0);

	/* force it to be null so finding bugs may be easier */
	*st = NULL;

	/* verify that at least one address is present */
	if ( optind == argc ){
		fprintf(stderr, "%s: no stream address specified.", program_name);
		return EINVAL;
	}

	/* parse first stream address */
	if ( (ret=stream_addr_aton(&addr, argv[optind], STREAM_ADDR_GUESS, 0)) != 0 ){
		fprintf(stderr, "%s: Failed to parse stream address: %s\n", program_name, caputils_error_string(ret));
		return ret;
	}

	/* open first stream */
	fprintf(stderr, "Opening %s stream: %s\n", type[stream_addr_type(&addr)], stream_addr_ntoa(&addr));
	if ( (ret=stream_open(st, &addr, iface, 0)) != 0 ) {
		fprintf(stderr, "%s: stream_open() failed with code 0x%08X: %s\n", program_name, ret, caputils_error_string(ret));
		return ret;
	}

	/* no secondary present */
	if ( ++optind == argc ){
		return 0;
	}

	if ( stream_addr_type(&addr) != STREAM_ADDR_ETHERNET ){
		fprintf(stderr, "%s: only ethernet streams support multiple addresses.\n", program_name);
		return EINVAL;
	}

	/* try secondary addresses */
	for ( int i = ++optind; i < argc; i++ ){
		if ( (ret=stream_addr_aton(&addr, argv[i], STREAM_ADDR_ETHERNET, 0)) != 0 ){
			fprintf(stderr, "%s: Failed to parse stream address: %s\n", program_name, caputils_error_string(ret));
			return ret;
		}

		if( (ret=stream_add(*st, &addr)) != 0 ) {
			fprintf(stderr, "%s: stream_add() failed with code 0x%08X: %s\n", program_name, ret, caputils_error_string(ret));
			return ret;
		}
	}

	return 0;
}

void stream_print_info(const struct stream* st, FILE* dst){
	struct file_version version;
	const char* mampid = stream_get_mampid(st);
	const char* comment = stream_get_comment(st);
	stream_get_version(st, &version);
	fprintf(dst, "%s caputils %d.%d stream\n", stream_addr_ntoa(&st->addr), version.major, version.minor);
	fprintf(dst, "     mpid: %s\n", mampid[0] != 0 ? mampid : "(unset)");
	fprintf(dst, "  comment: %s\n", comment ? comment : "(unset)");
}
