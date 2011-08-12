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

static void homogenize_eth_addr(char* buf){
  /* eth addr with : */
  if ( buf[2] == ':' ){
    return; /* do nothing */
  }

  /* convert - to : */
  if ( buf[2] == '-' ){
    for ( int i = 0; i < 6; i++ ){
      buf[i*3+2] = ':';
    }
    return;
  }

  /* if no : or - is found, insert : into the buffer by starting at the
   * first pair (LSB) and moving it to the new position. */
  
  char* tmp = &buf[3*5+2];
  *(tmp--) = 0;
  for ( int i = 5; i >= 1; i-- ){
    *(tmp--) = buf[1+i*2];
    *(tmp--) = buf[  i*2];
    *(tmp--) = ':';
  }
}

int stream_addr_aton(stream_addr_t* dst, const char* src, enum AddressType type, int flags){
  char buf[48];          /* larger than max, just in case user provides large */
  strncpy(buf, src, 48); /* input, will bail out later on bad data. */

  memset(dst->buffer, 0, 26);
  dst->_type = htons(type);
  dst->_flags = htons(flags);

  switch( type ){
  case STREAM_ADDR_GUESS:
    /* try tcp/udp */
    if ( strncmp("tcp://", src, 6) == 0 ){
      return stream_addr_aton(dst, src+6, STREAM_ADDR_TCP, flags);
    } else if ( strncmp("udp://", src, 6) == 0 ){
      return stream_addr_aton(dst, src+6, STREAM_ADDR_UDP, flags);
    }

    /* try ethernet */
    if ( stream_addr_aton(dst, src, STREAM_ADDR_ETHERNET, flags) == 0 ){
      return 0;
    }

    /* last option: parse as local filename */
    return stream_addr_aton(dst, src, STREAM_ADDR_CAPFILE, flags | STREAM_ADDR_LOCAL);

  case STREAM_ADDR_TCP: // TCP
  case STREAM_ADDR_UDP: // UDP
    // DESTADDR is ipaddress:port
    {
      char* ip = buf;
      strncpy(buf, src, 48);

      dst->in_port = htons(0x0810); /* default port */

      char* separator = strchr(buf, ':');
      if( separator ) {
	*separator = 0;
	dst->in_port = htons(atoi(separator+1));
      }

      dst->in_addr.s_addr = inet_addr(ip);

      if ( dst->in_addr.s_addr == INADDR_NONE ){
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
    if ( flags & STREAM_ADDR_LOCAL ){
      dst->local_filename = src;
    } else {
      strncpy(dst->filename, src, 22);
      dst->filename[21] = 0; /* force null-terminator */
    }
    break;
  }

  return 0;
}

int stream_addr_str(stream_addr_t* dst, const char* src, int flags){
  dst->_type = htons(STREAM_ADDR_CAPFILE);
  dst->_flags = htons(STREAM_ADDR_LOCAL|flags);
  dst->local_filename = src;
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
    written = snprintf(buf, bytes, "%s://%s:%d", stream_addr_type(src) == STREAM_ADDR_UDP ? "udp" : "tcp", inet_ntoa(src->in_addr), ntohs(src->in_port));
    break;
  case STREAM_ADDR_ETHERNET:
    hexdump_address_r(&src->ether_addr, buf);
    break;
  case STREAM_ADDR_CAPFILE:
    if ( ntohl(src->_flags) & STREAM_ADDR_LOCAL ){
      strncpy(buf, src->local_filename, bytes);
    } else {
      strncpy(buf, src->filename, bytes);
    }
    buf[bytes-1] = 0; /* force null-terminator */
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
