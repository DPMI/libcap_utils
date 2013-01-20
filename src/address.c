#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "caputils/address.h"
#include "caputils_int.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

/**
 * like strtok but works with sequential delimiters
 */
static char* strtok2(char* str, char* delim){
	static char* next = NULL;

	if ( !str ){
		str = next;
	}

	if ( !str ){
		return NULL;
	}

	char* tmp = strpbrk(str, delim);
	if ( !tmp ){
		next = NULL;
		return str;
	}

	*tmp = 0;
	next = tmp+1;

	return str;
}

static void homogenize_eth_addr(char* buf){
	const size_t len = strlen(buf);

	/* convert dash to colon */
	for ( int i = 0; i < 17; i++ ){
		if ( buf[i] == '-' ) buf[i] = ':';
	}

	char tmp[17] = {0,};
	char* cur = tmp;
	char* pair = strtok2(buf, ":");
	while ( pair ){
		char* next = strtok2(NULL, ":");

		switch ( strlen(pair) ){
		case 12: /* no delimiter */
			/* insert colon into the buffer by starting at the first pair (LSB) and
			 * moving it to the new position. */
			{
				char* ptr = &buf[3*5+2];
				*(ptr--) = 0;
				for ( int i = 5; i >= 1; i-- ){
					*(ptr--) = buf[1+i*2];
					*(ptr--) = buf[  i*2];
					*(ptr--) = ':';
				}
			}

			return; /* nothing more to do */

		case 2: /* two digits */
			cur += sprintf(cur, "%s", pair);
			break;

		case 1: /* 1 digit */
			cur += sprintf(cur, "0%s", pair);
			break;

		case 0: /* no digits means double delimiter */
			break;

		default: /* something else, just bail out */
			return;
		}

		if ( next ){
			*cur++ = ':';
		}

		pair = next;
	}

	memcpy(buf, tmp, 17);

	/* look for :: and fill in blanks */
	for ( unsigned int i = 0; i < len-1; i++ ){
		if ( buf[i  ] != ':' ) continue;
		if ( buf[i+1] != ':' ) continue;

		/*   0 1 : 0 0 : 0 0 : 0 0 : 0 0 : 0 1
		 *   0 1 : : 0 1                 ^
		 * p1 -----^     ^               |
		 * p2 -----------+               |
		 * p3 ---------------------------+
		 */

		const unsigned int p1 = i+1;
		unsigned int p2 = p1; for ( ; buf[p2] != 0; p2++ ){}
		const unsigned int digits = p2-p1;
		const unsigned int p3 = 17 - digits;

		/* move right part to the end */
		memcpy(&buf[p3], &buf[p1], digits);

		/* fill blanks */
		for ( unsigned int j = p1; j < p3; j += 3 ){
			buf[j  ] = '0';
			buf[j+1] = '0';
			buf[j+2] = ':';
		}
	}
}

int stream_addr_aton(stream_addr_t* dst, const char* src, enum AddressType type, int flags){
	char buf[48] = {0,};   /* larger than max, just in case user provides large */
	strncpy(buf, src, 48); /* input, will bail out later on bad data. */

	stream_addr_reset(dst);
	dst->_type = htons(type);
	dst->_flags = htons(flags);

	switch( type ){
	case STREAM_ADDR_GUESS:
		{
			char* delim = strstr(buf, "://");

			/* check if prefix is set */
			if ( delim ){
				*delim = 0;
				const char* prefix = buf;
				const char* addr = delim + 3;

				if ( strcasecmp("tcp", prefix) == 0 ){
					return stream_addr_aton(dst, addr, STREAM_ADDR_TCP, flags);
				} else if ( strcasecmp("udp", prefix) == 0 ){
					return stream_addr_aton(dst, addr, STREAM_ADDR_UDP, flags);
				} else if ( strcasecmp("eth", prefix) == 0 ){
					return stream_addr_aton(dst, addr, STREAM_ADDR_ETHERNET, flags);
				} else if ( strcasecmp("file", prefix) == 0 ){
					return stream_addr_aton(dst, src+7, STREAM_ADDR_CAPFILE, flags | STREAM_ADDR_LOCAL);
				} else if ( strcasecmp("fifo", prefix) == 0 ){
					return stream_addr_aton(dst, src+7, STREAM_ADDR_FIFO, flags | STREAM_ADDR_LOCAL | STREAM_ADDR_UNLINK);
				}

				return EINVAL;
			}

			/* try ethernet */
			if ( stream_addr_aton(dst, src, STREAM_ADDR_ETHERNET, flags) == 0 ){
				return 0;
			}

			/* last option: parse as local filename */
			return stream_addr_aton(dst, src, STREAM_ADDR_CAPFILE, flags | STREAM_ADDR_LOCAL);
		}

	case STREAM_ADDR_TCP: // TCP
	case STREAM_ADDR_UDP: // UDP
		// DESTADDR is ipaddress:port
		{
			char* ip = buf;
			strncpy(buf, src, 48);

			dst->ipv4.sin_family = AF_INET;
			dst->ipv4.sin_port = htons(0x0810); /* default port */

			char* separator = strchr(buf, ':');
			if( separator ) {
				*separator = 0;
				dst->ipv4.sin_port = htons(atoi(separator+1));
			}

			dst->ipv4.sin_addr.s_addr = inet_addr(ip);

			if ( dst->ipv4.sin_addr.s_addr == INADDR_NONE ){
				return EINVAL;
			}
		}
		break;

	case STREAM_ADDR_ETHERNET: // Ethernet
		homogenize_eth_addr(buf);

		if ( !eth_aton(&dst->ether_addr, buf) ){
			return EINVAL;
		}
		break;

	case STREAM_ADDR_CAPFILE: // File
	case STREAM_ADDR_FIFO:
		if ( flags & STREAM_ADDR_LOCAL ){
			dst->local_filename = src;
			if ( flags &  STREAM_ADDR_DUPLICATE ){
				dst->int_filename = strdup(dst->local_filename);
			}
		} else {
			strncpy(dst->filename, src, 22);
			dst->filename[21] = 0; /* force null-terminator */
		}
		break;

	case STREAM_ADDR_FP:
		return EINVAL;

	}

	return 0;
}

int stream_addr_str(stream_addr_t* dst, const char* src, int flags){
	stream_addr_reset(dst);

	dst->_type = htons(STREAM_ADDR_CAPFILE);
	dst->_flags = htons(STREAM_ADDR_LOCAL|flags);
	dst->local_filename = src;

	if ( flags & STREAM_ADDR_DUPLICATE ){
		dst->int_filename = strdup(dst->local_filename);
	}
	return 0;
}

int stream_addr_fp(stream_addr_t* dst, FILE* fp, int flags){
	dst->_type = htons(STREAM_ADDR_FP);
	dst->_flags = htons(STREAM_ADDR_LOCAL|flags);
	dst->fp = fp;
	return 0;
}

const char* stream_addr_ntoa(const stream_addr_t* src){
	static char buf[1024];
	return stream_addr_ntoa_r(src, buf, 1024);
}

const char* stream_addr_ntoa_r(const stream_addr_t* src, char* buf, size_t bytes){
	int __attribute__((unused)) written = 0;

	switch(stream_addr_type(src)){
	case STREAM_ADDR_GUESS:
		abort();

	case STREAM_ADDR_TCP:
	case STREAM_ADDR_UDP:
		written = snprintf(buf, bytes, "%s://%s:%d", stream_addr_type(src) == STREAM_ADDR_UDP ? "udp" : "tcp", inet_ntoa(src->ipv4.sin_addr), ntohs(src->ipv4.sin_port));
		break;
	case STREAM_ADDR_ETHERNET:
		written = snprintf(buf, bytes, "eth://%s", hexdump_address(&src->ether_addr));
		break;
	case STREAM_ADDR_FIFO:
		written = snprintf(buf, bytes, "fifo://%s", src->local_filename);
		break;

	case STREAM_ADDR_CAPFILE:
		if ( stream_addr_have_flag(src, STREAM_ADDR_LOCAL) ){
			strncpy(buf, src->local_filename, bytes);
		} else {
			strncpy(buf, src->filename, bytes);
		}
		buf[bytes-1] = 0; /* force null-terminator */
		break;
	case STREAM_ADDR_FP:
		snprintf(buf, bytes, "/dev/fd/%d", fileno(src->fp));
		break;
	}

	assert(written < bytes);
	return buf;
}

enum AddressType stream_addr_type(const stream_addr_t* addr){
	return (enum AddressType)ntohs(addr->_type);
}

int stream_addr_flags(const stream_addr_t* addr){
	return ntohs(addr->_flags);
}

int stream_addr_have_flag(const stream_addr_t* addr, enum AddressFlags flag){
	return ntohs(addr->_flags) & flag;
}

void stream_addr_reset(stream_addr_t* addr){
	if ( stream_addr_type(addr) == STREAM_ADDR_CAPFILE &&
	     stream_addr_have_flag(addr, STREAM_ADDR_DUPLICATE) ){
		free(addr->int_filename);
	}

	memset(addr, 0, sizeof(stream_addr_t));
}

int stream_addr_is_set(const stream_addr_t* addr){
	/* potentially another address type might have the first bytes as a zero so
	 * the type is also checked */
	return addr->_type != 0 || addr->filename[0] != 0;
}
