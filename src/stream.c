/**
 * libcap_utils - DPMI capture utilities
 * Copyright (C) 2003-2013 (see AUTHORS)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <caputils/caputils.h>
#include <caputils/capture.h>
#include <caputils/log.h>
#include "caputils_int.h"
#include "stream.h"
#include "format/format.h"

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

int stream_alloc(struct stream** stptr, enum protocol_t protocol, size_t size, size_t buffer_size, size_t mtu){
	assert(stptr);

	if ( buffer_size == 0 ){
		buffer_size = 175000; /* default buffer size */
	}

	/* the buffer is always placed after the struct */
	struct stream* st = (struct stream*)malloc(size + buffer_size);
	memset(st, 0, size + buffer_size);
	*stptr = st;

	st->type = protocol;
	st->comment = NULL;
	st->buffer = (char*)st + size; /* calculate pointer to buffer */
	st->buffer_size = buffer_size;

	st->expSeqnr = 0;
	st->readPos = 0;
	st->writePos = 0;
	st->flushed = 0;
	st->num_addresses = 0;
	st->if_mtu = mtu;
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
	st->flush = NULL;

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

	case STREAM_ADDR_UDP:
		ret = stream_udp_open(stptr, &dest->ipv4, iface);
		break;

	case STREAM_ADDR_TCP:
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
	const char* filename;
	int flags = stream_addr_flags(dest);
	int ret = ERROR_NOT_IMPLEMENTED; /* initialized to silence certain versions of gcc */

	enum AddressType type = stream_addr_type(dest);
	switch ( type ){
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

	case STREAM_ADDR_UDP:
		ret = stream_udp_create(stptr, &dest->ipv4, nic, flags);
		break;

	case STREAM_ADDR_TCP:
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
	if ( st->flushed==1 ){
		return -1;
	}

	/**
	 *                                  available
	 *                                 +-----+
	 *                                 |     |
	 *  +------------ buffer size -----)-----+
	 *  v                              v     v
	 *  +====================================+
	 *  |  |            BUFFER         |     |
	 *  +====================================+
	 *     ^                           ^     ^
	 *     +--- read pos   write pos --+     |
	 *     |                                 |
	 *     +------------- left --------------+
	 */

	size_t available = st->buffer_size - st->writePos;
	size_t left = st->buffer_size - st->readPos;

	/* don't need to fill file buffer unless drained */
	struct cap_header* cp = (struct cap_header*)(st->buffer + st->readPos);
	if ( available == 0 && left > sizeof(struct cap_header) && left > (sizeof(struct cap_header)+cp->caplen) ){
		return 0;
	}

	/* copy old content */
	if ( st->readPos > 0 ){
		size_t bytes = st->writePos - st->readPos;
		memmove(st->buffer, st->buffer + st->readPos, bytes); /* move content */
		st->writePos = bytes;
		st->readPos = 0;
		available = st->buffer_size - bytes;
	}

	char* dst = st->buffer + st->writePos;
	int ret = st->fill_buffer(st, timeout, dst, available);
	if ( ret > 0 ){ /* common case (ret is number of bytes) */
		st->writePos += ret;
		return 0;
	} else if ( ret < 0 ){ /* failed to read */
		return errno;
	} else { /* EOF, TCP shutdown etc */
		return -1;
	}
}

int stream_read(struct stream *st, cap_head** data, struct filter *my_Filter, struct timeval* timeout){
	if ( st->read ){
		return st->read(st, data, my_Filter, timeout);
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
		if( st->writePos - st->readPos < sizeof(struct cap_header) ){
			if ( !timeout ){
				tv.tv_sec = 1; /* always read for one sec */
			}

			switch ( (ret=fill_buffer(st, &tv)) ){
			case 0:
				continue; /* retry, buffer is not full */

			case EAGAIN:
				/* if a timeout occurred but there is enough data to read a packet it is
				 * not considered an error. */
				if ( st->writePos - st->readPos >= sizeof(struct cap_header) ){
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
		if ( (ret=fill_buffer(st, &zero)) != 0 && ret != EAGAIN && ret != -1 ){
			return ret;
		}

		// We have some data in the buffer.
		struct cap_header* cp = (struct cap_header*)(st->buffer + st->readPos);
		const size_t packet_size = sizeof(struct cap_header) + cp->caplen;
		const size_t start_pos = st->readPos;
		const size_t end_pos = start_pos + packet_size;

		if( end_pos > st->writePos ) {
			if ( (ret=fill_buffer(st, timeout)) != 0 ){
				return ret; /* could not read */
			}

			continue;
		}

		/* set next packet and advance the read pointer */
		*data = cp;
		st->readPos += packet_size;
		st->stat.read++;
		st->stat.buffer_usage = st->writePos - st->readPos;

		filterStatus = 1; /* match by default, i.e. if no filter is used. */
		if ( my_Filter ){
			filterStatus = filter_match(my_Filter, cp->payload, cp);
		}
	} while(filterStatus==0);

	st->stat.matched++;
	return 0;
}

int stream_read_cb(stream_t st, stream_read_callback_t callback, struct filter* filter, const struct timeval* timeout){
	/* A short timeout is used to allow the application to "breathe", i.e
	 * terminate if SIGINT was received. */
	struct timeval tv = {1,};
	if ( timeout ) tv = *timeout;

	/* Read the next packet */
	cap_head* cp;
	const int ret = stream_read(st, &cp, filter, &tv);
	if ( ret == EAGAIN ){
		return 0;
	} else if ( ret == -1 || ret == EINTR ){
		return ret; /* properly closed stream or user-signaled request for shutdown */
	} else if ( ret != 0 ){
		fprintf(stderr, "stream_read() returned 0x%08X: %s\n", ret, caputils_error_string(ret));
		return ret;
	}

	return callback(st, cp);
}

int stream_peek(stream_t st, cap_head** header, struct filter* filter){
	if ( st->read ){
		fprintf(stderr, "stream_peek not implemented for this stream type\n");
		abort();
	}

	struct timeval timeout = {0,0};

	int ret;
	int match = 0;
	do {
		if( st->writePos - st->readPos < sizeof(struct cap_header) ){
			switch ( (ret=fill_buffer(st, &timeout)) ){
			case 0: continue;
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
			case 0: continue;
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
	stream_addr_t addr = STREAM_ADDR_INITIALIZER;

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
		goto out;
	}

	/* open first stream */
	fprintf(stderr, "Opening %s stream: %s\n", type[stream_addr_type(&addr)], stream_addr_ntoa(&addr));
	if ( (ret=stream_open(st, &addr, iface, buffer_size)) != 0 ) {
		fprintf(stderr, "%s: stream_open(..) returned with code %d: %s\n", program_name, ret, caputils_error_string(ret));
		goto out;
	}

	/* no secondary present */
	if ( ++optind >= argc ){
		stream_addr_reset(&addr);
		ret = 0;
		goto out;
	}

	if ( !(stream_addr_type(&addr) == STREAM_ADDR_ETHERNET || stream_addr_type(&addr) == STREAM_ADDR_UDP) ){
		fprintf(stderr, "%s: only ethernet and udp streams support multiple addresses (multicasting).\n", program_name);
		ret = EINVAL;
		goto out;
	}

	/* try secondary addresses */
	for ( int i = optind++; i < argc; i++ ){
		if ( (ret=stream_addr_aton(&addr, argv[i], STREAM_ADDR_GUESS, 0)) != 0 ){
			fprintf(stderr, "%s: Failed to parse stream address: %s\n", program_name, caputils_error_string(ret));
			goto out;
		}

		fprintf(stderr, "Adding %s stream: %s\n", type[stream_addr_type(&addr)], stream_addr_ntoa(&addr));
		if( (ret=stream_add(*st, &addr)) != 0 ) {
			fprintf(stderr, "%s: stream_add() failed with code 0x%08X: %s\n", program_name, ret, caputils_error_string(ret));
			goto out;
		}
	}

	out:
	stream_addr_reset(&addr);
	return ret;
}

void stream_print_info(const stream_t st, FILE* dst){
	struct file_version version;
	const char* mampid = stream_get_mampid(st);
	const char* comment = stream_get_comment(st);
	stream_get_version(st, &version);
	fprintf(dst, "%s caputils %d.%d stream\n", stream_addr_ntoa(&st->addr), version.major, version.minor);

	fputs("     mpid: ", dst);
	fputs_printable(mampid[0] != 0 ? mampid : "(unset)", -1, dst);
	fputc('\n', dst);

	fputs("  comment: ", dst);
	fputs_printable(comment ? comment : "(unset)", -1, dst);
	fputc('\n', dst);
}

int stream_add(struct stream* st, const stream_addr_t* addr){
	if ( !(st && addr) ) return EINVAL;

	switch ( stream_addr_type(addr) ){
	case STREAM_ADDR_ETHERNET:
#ifdef HAVE_PFRING
		return stream_pfring_add(st, &addr->ether_addr);
#else
		return stream_ethernet_add(st, &addr->ether_addr);
#endif

	case STREAM_ADDR_UDP:
		return stream_udp_add(st, addr->ipv4.sin_addr);

	default:
		return ERROR_INVALID_PROTOCOL;
	}
}

unsigned int stream_num_address(const stream_t st){
	return st->num_addresses;
}

int stream_flush(stream_t st){
	if ( st->flush ){
		return st->flush(st);
	}
	return 0;
}

/**
 * Calculate the number of bytes to expected from this frame.
 */
static size_t sendheader_bytes(const struct sendhead* sh){
	static const size_t header_size = sizeof(struct ethhdr) + sizeof(struct sendhead);
	int n = ntohl(sh->nopkts);
	size_t expected = header_size;
	const char* ptr = ((const char*)sh) + sizeof(struct sendhead);
	while ( n --> 0 ){
		const struct cap_header* cp = (const struct cap_header*)ptr;
		if ( cp->caplen == 0 ){
			fprintf(stderr, "cp->caplen == 0, discarding frame.\n");
			return 0;
		}
		const size_t size = sizeof(struct cap_header) + cp->caplen;
		expected += size;
		ptr += size;
	}
	return expected;
}

int valid_framesize(size_t actual, const struct sendhead* sh){
	const size_t expected = sendheader_bytes(sh);
	if ( actual != expected ){
		fprintf(stderr,
		        "invalid measurement frame received.\n"
		        "  seqnum: 0x%04X [raw: 0x%08X]\n"
		        "  nopkts: %d [raw: 0x%08X]\n"
		        "  frame size: %zd bytes\n"
		        "  expected: %zd bytes\n",
		        ntohl(sh->sequencenr), sh->sequencenr, ntohl(sh->nopkts), sh->nopkts, actual, expected);
		return 0;
	}
	return 1;
}
