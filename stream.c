#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <caputils/caputils.h>
#include <caputils/capture.h>
#include <caputils/log.h>
#include "caputils_int.h"
#include "stream.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>

int stream_alloc(struct stream** stptr, enum protocol_t protocol, size_t size, size_t buffer_size){
	assert(stptr);

	if ( buffer_size == 0 ){
		buffer_size = 175000; /* default buffer size */
	}

	/* the buffer is always placed after the struct */
	struct stream* st = (struct stream*)malloc(size + buffer_size);
	*stptr = st;

	st->type = protocol;
	st->comment = NULL;
	st->buffer = (char*)st + size; /* calculate pointer to buffer */
	st->buffer_size = buffer_size;

	st->expSeqnr = 0;
	st->writePos=0;
	st->readPos=0;
	st->flushed = 0;
	st->num_addresses = 1;
	st->if_loopback = 0;
	st->stat.read = 0;
	st->stat.recv = 0;
	st->stat.matched = 0;
	st->stat.buffer_size = buffer_size;
	st->stat.buffer_usage = 0;

	/* callbacks */
	st->fill_buffer = NULL;
	st->destroy = NULL;
	st->write = NULL;
	st->read = NULL;

	/* reset memory */
	memset(st->buffer, 0, buffer_size);

	/* initialize file_header */
	st->FH.comment_size = 0;
	memset(st->FH.mpid, 0, 200); /* @bug what is 200? why is not [0] = 0 enought? */

	return 0;
}

/**
 * Return current time as a string.
 * @return pointer to internal memory, not threadsafe. Subsequent calls will overwrite data.
 */
static const char* timestr(){
	static char timestr[64];

	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	strftime(timestr, sizeof(timestr), "%a, %d %b %Y %H:%M:%S %z", &tm);

	return timestr;
}

void match_inc_seqnr(const struct stream* st, long unsigned int* restrict seq, const struct sendhead* restrict sh){
	const int expected = *seq;
	const int got = ntohl(sh->sequencenr);

	/* detect loopback device with duplicate packets */
	const int loopback_dup = st->if_loopback && expected == got + 1;
	if ( __builtin_expect(loopback_dup, 0) ){
		static int loopback_warning = 1;
		if ( loopback_warning ){
			fprintf(stderr, "[%s] Warning: a loopback device receiving duplicate packets has been detected, duplicates will be ignored but it will incur degraded performance.\n", timestr());
			loopback_warning = 0;
		}
		return;
	}

	/* validate sequence number */
	if( __builtin_expect(expected != got, 0) ){
		fprintf(stderr,"[%s] Mismatch of sequence numbers. Expected %d got %d (%d frame(s) missing, pkgcount: %"PRIu64")\n", timestr(), expected, got, (got-expected), st->stat.recv);
		*seq = ntohl(sh->sequencenr); /* reset sequence number */
		abort();
	}

	/* increment sequence number (next packet is expected to have +1) */
	(*seq)++;

	/* wrap sequence number */
	if( *seq >= 0xFFFF ){
		*seq = 0;
	}
}

void stream_get_version(const stream_t st, struct file_version* dst){
	dst->major = st->FH.version.major;
	dst->minor = st->FH.version.minor;
}

const char* stream_get_comment(const stream_t st){
	return st->comment;
}

const char* stream_get_mampid(const stream_t st){
	return st->FH.mpid;
}

const struct stream_stat* stream_get_stat(const stream_t st){
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

int stream_open(stream_t* stptr, const stream_addr_t* dest, const char* iface, size_t buffer_size){
	int ret = EINVAL;

	switch(stream_addr_type(dest)){
		/* case PROTOCOL_TCP_UNICAST: */
		/*   return stream_tcp_init(myStream, address, port); */

		/* case PROTOCOL_UDP_MULTICAST: */
		/*   return stream_udp_init(myStream, address, port); */

	case STREAM_ADDR_ETHERNET:
#ifdef HAVE_PFRING
		ret = stream_pfring_open(stptr, &dest->ether_addr, iface, buffer_size);
#else
		ret = stream_ethernet_open(stptr, &dest->ether_addr, iface, buffer_size);
#endif
		break;

	case STREAM_ADDR_FIFO:
		if ( (ret=mkfifo(dest->local_filename, 0660)) == -1 ){
			if ( errno == EEXIST ){
				return ERROR_CAPFILE_FIFO_EXIST; /* a more descriptive error message */
			}
			return errno;
		}
		if ( (ret=stream_file_open(stptr, NULL, dest->local_filename, buffer_size)) != 0 ){
			unlink(dest->local_filename);
		}
		break;

	case STREAM_ADDR_CAPFILE:
		ret = stream_file_open(stptr, NULL, stream_addr_have_flag(dest, STREAM_ADDR_LOCAL) ? dest->local_filename : dest->filename, buffer_size);
		break;

	case STREAM_ADDR_FP:
		ret = stream_file_open(stptr, dest->fp, NULL, buffer_size);
		break;

	case STREAM_ADDR_GUESS:
		return EINVAL;

	case STREAM_ADDR_TCP:
	case STREAM_ADDR_UDP:
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

int stream_create(stream_t* stptr, const stream_addr_t* dest, const char* nic, const char* mpid, const char* comment){
	/* struct ifreq ifr; */
	/* int ifindex=0; */
	/* int socket_descriptor=0; */
	/* int ret; */
	/* struct sockaddr_in destination; */
	/* struct ether_addr ethernet_address; */
	const char* filename;
	int flags = stream_addr_flags(dest);
	int ret = ERROR_NOT_IMPLEMENTED; /* initialized to silence certain versions of gcc */

	switch ( stream_addr_type(dest) ){
	case STREAM_ADDR_ETHERNET:
#ifdef HAVE_PFRING
		ret = stream_pfring_create(stptr, &dest->ether_addr, nic, mpid, comment, flags);
#else
		ret = stream_ethernet_create(stptr, &dest->ether_addr, nic, mpid, comment, flags);
#endif
		break;

	case STREAM_ADDR_FIFO:
		if ( (ret=mkfifo(dest->local_filename, 0660)) == -1 ){
			if ( errno == EEXIST ){
				return ERROR_CAPFILE_FIFO_EXIST; /* a more descriptive error message */
			}
			return errno;
		}
		if ( (ret=stream_file_create(stptr, NULL, dest->local_filename, mpid, comment, flags)) != 0 ){
			unlink(dest->local_filename);
		}
		break;

	case STREAM_ADDR_CAPFILE:
		filename = stream_addr_have_flag(dest, STREAM_ADDR_LOCAL) ? dest->local_filename : dest->filename;
		ret = stream_file_create(stptr, NULL, filename, mpid, comment, flags);
		break;

	case STREAM_ADDR_FP:
		ret = stream_file_create(stptr, dest->fp, NULL, mpid, comment, flags);
		break;

	case STREAM_ADDR_GUESS:
		return EINVAL;

	case STREAM_ADDR_TCP:
	case STREAM_ADDR_UDP:
		return ERROR_NOT_IMPLEMENTED;
	}

	/** @note Only shallow copy, it might cause issues if using a local path which
	 * is referenced and freed after stream_open. Can only safely copy if open
	 * succeeded because there is no guarantee stream is allocated if it fails.  */
	if ( ret == 0 ){
		(*stptr)->addr = *dest;
	}

	return ret;

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

int stream_close(stream_t st){
	if ( st == NULL ) return 0;
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

	if ( size == 0 ){
		logmsg(stderr, "stream", "stream_write called with invalid size 0\n");
		return EINVAL;
	}

	return outStream->write(outStream, data, size);
}

int stream_write_separate(stream_t st, const caphead_t head, const void* data, size_t size){
	assert(outStream);
	assert(outStream->write);

	if ( size == 0 ){
		logmsg(stderr, "stream", "stream_write called with invalid size 0\n");
		return EINVAL;
	}

	int ret;
	if ( (ret=st->write(st, head, sizeof(struct cap_header))) != 0 ) return ret;
	if ( (ret=st->write(st, data, size)) != 0 ) return ret;
	return 0;
}

int stream_copy(stream_t st, const struct cap_header* head){
	return stream_write(st, head, sizeof(struct cap_header) + head->caplen);
}

static int fill_buffer(stream_t st, struct timeval* timeout){
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
	if ( myStream->read ){
		return myStream->read(myStream, data, my_Filter, timeout);
	}

	int filterStatus=0;
	int skip_counter=-1;
	int ret = 0;

	/* as a precaution, reset the datapoint to NULL so errors will be easier to track down */
	*data = NULL;

	/* always use a timeout so it won't block indefinitely. This helps when
	 * there is very little traffic. */
	struct timeval tv = {1,0};
	if ( timeout ){
		tv = *timeout;
	}

	do {
		skip_counter++;

		/* bufferSize tells how much data there is available in the buffer */
		if( myStream->writePos - myStream->readPos < sizeof(struct cap_header) ){
			if ( !timeout ){
				tv.tv_sec = 1; /* always read for one sec */
			}

			switch ( (ret=fill_buffer(myStream, &tv)) ){
			case 0:
				continue; /* retry, buffer is not full */

			case EAGAIN:
				/* if a timeout occurred but there is enough data to read a packet it is
				 * not considered an error. */
				if ( myStream->writePos - myStream->readPos >= sizeof(struct cap_header) ){
					continue;
				}

				/* If the user requested a blocking call we must retry no matter what */
				if ( !timeout ){
					continue;
				}

				/* fallthrough */
			default:
				return ret; /* could not read */
			}
		}

		/* Try to read data into the buffer (using a zero timeout so it won't block)
		 * to keep the buffer full and reducing load on the network buffers.*/
		struct timeval zero = {0,0};
		if ( (ret=fill_buffer(myStream, &zero)) != 0 && ret != EAGAIN && ret != -1 ){
			return ret;
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

		if( end_pos > myStream->writePos ) {
			if ( (ret=fill_buffer(myStream, timeout)) != 0 ){
				return ret; /* could not read */
			}

			continue;
		}

		/* set next packet and advance the read pointer */
		*data = cp;
		myStream->readPos += packet_size;
		myStream->stat.read++;
		myStream->stat.buffer_usage = myStream->writePos - myStream->readPos;

		filterStatus = 1; /* match by default, i.e. if no filter is used. */
		if ( my_Filter ){
			filterStatus = filter_match(my_Filter, cp->payload, cp);
		}
	} while(filterStatus==0);

	myStream->stat.matched++;
	return 0;
}

int stream_peek(stream_t st, cap_head** header, const struct filter* filter){
	if ( st->read ){
		fprintf(stderr, "stream_peek not implemented for this stream type\n");
		abort();
	}

	struct timeval timeout = {0,0};

	int ret;
	int match;
	do {
		if( st->writePos - st->readPos < sizeof(struct cap_header) ){
			switch ( (ret=fill_buffer(st, &timeout)) ){
			case 0: return EAGAIN;
			default: return ret;
			}
		}

		struct cap_header* cp = (struct cap_header*)(st->buffer + st->readPos);
		const size_t packet_size = sizeof(struct cap_header) + cp->caplen;
		const size_t start_pos = st->readPos;
		const size_t end_pos = start_pos + packet_size;

		if ( cp->caplen == 0 ){
			return ERROR_CAPFILE_INVALID;
		}

		if( end_pos > st->writePos ) {
			switch ( (ret=fill_buffer(st, &timeout)) ){
			case 0: return EAGAIN;
			default: return ret;
			}
		}

		*header = cp;

		match = 1;
		if ( filter ){
			match = filter_match(filter, cp->payload, cp);
		}
	} while ( match == 0 );

	return 0;
}

static const char* type[6] = {"file", "ethernet", "udp", "tcp", "file", "fifo"};
int stream_from_getopt(stream_t* st, char* argv[], int optind, int argc, const char* iface, const char* defaddr, const char* program_name, size_t buffer_size){
	int ret;
	stream_addr_t addr;
	memset(&addr, 0, sizeof(stream_addr_t));

	/* force it to be null so finding bugs may be easier */
	*st = NULL;

	const char* address = defaddr;
	if ( optind < argc ){
		address = argv[optind];
	}

	/* verify that at least one address is present */
	if ( !address ){
		fprintf(stderr, "%s: no stream address specified.\n", program_name);
		return EINVAL;
	}

	/* parse '-' as stdin */
	if ( strcmp(address, "-") == 0 ){
		if ( isatty(STDIN_FILENO) ){
			fprintf(stderr, "%s: Cannot read from stdin when connected to a terminal and no stream address was specified.\n", program_name);
			return EINVAL;
		}
		address = "/dev/stdin";
	}

	/* parse first stream address */
	if ( (ret=stream_addr_aton(&addr, address, STREAM_ADDR_GUESS, 0)) != 0 ){
		fprintf(stderr, "%s: Failed to parse stream address: %s\n", program_name, caputils_error_string(ret));
		return ret;
	}

	/* ensure an interface was specified for ethernet streams */
	if ( stream_addr_type(&addr) == STREAM_ADDR_ETHERNET && !iface ){
		fprintf(stderr, "%s: ethernet stream requested but no interface was specified.\n", program_name);
		return EINVAL;
	}

	/* open first stream */
	fprintf(stderr, "Opening %s stream: %s\n", type[stream_addr_type(&addr)], stream_addr_ntoa(&addr));
	if ( (ret=stream_open(st, &addr, iface, buffer_size)) != 0 ) {
		fprintf(stderr, "%s: stream_open(..) returned with code %d: %s\n", program_name, ret, caputils_error_string(ret));
		return ret;
	}

	/* no secondary present */
	if ( ++optind >= argc ){
		return 0;
	}

	if ( stream_addr_type(&addr) != STREAM_ADDR_ETHERNET ){
		fprintf(stderr, "%s: only ethernet streams support multiple addresses.\n", program_name);
		return EINVAL;
	}

	/* try secondary addresses */
	for ( int i = optind++; i < argc; i++ ){
		if ( (ret=stream_addr_aton(&addr, argv[i], STREAM_ADDR_ETHERNET, 0)) != 0 ){
			fprintf(stderr, "%s: Failed to parse stream address: %s\n", program_name, caputils_error_string(ret));
			return ret;
		}

		fprintf(stderr, "Adding %s stream: %s\n", type[stream_addr_type(&addr)], stream_addr_ntoa(&addr));
		if( (ret=stream_add(*st, &addr)) != 0 ) {
			fprintf(stderr, "%s: stream_add() failed with code 0x%08X: %s\n", program_name, ret, caputils_error_string(ret));
			return ret;
		}
	}

	return 0;
}

void stream_print_info(const stream_t st, FILE* dst){
	struct file_version version;
	const char* mampid = stream_get_mampid(st);
	const char* comment = stream_get_comment(st);
	stream_get_version(st, &version);
	fprintf(dst, "%s caputils %d.%d stream\n", stream_addr_ntoa(&st->addr), version.major, version.minor);
	fprintf(dst, "     mpid: %s\n", mampid[0] != 0 ? mampid : "(unset)");
	fprintf(dst, "  comment: %s\n", comment ? comment : "(unset)");
}

int stream_add(struct stream* st, const stream_addr_t* addr){
	if ( !st || stream_addr_type(addr) != STREAM_ADDR_ETHERNET ){
		return EINVAL;
	}

	if ( st->type != PROTOCOL_ETHERNET_MULTICAST ){
		return ERROR_INVALID_PROTOCOL;
	}

	st->num_addresses++;

#ifdef HAVE_PFRING
	return stream_pfring_add(st, &addr->ether_addr);
#else
	return stream_ethernet_add(st, &addr->ether_addr);
#endif
}

unsigned int stream_num_address(const stream_t st){
	return st->num_addresses;
}
