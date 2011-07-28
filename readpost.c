/***************************************************************************
                          readpost.c  -  description
                             -------------------
    begin                : Mnn Aug 1 2004
    copyright            : (C) 2005 by Patrik Arlos
    email                : Patrik.Arlos@bth.se
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/
/***************************************************************************
 This function reads a captured packet from the file and stores it in data.
  The function returns 1 until the file ends and a 0 is returned.
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "caputils/caputils.h"
#include "caputils_int.h"
#include "stream.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>

int fill_buffer(struct stream* st){
  if( st->flushed==1 ){
    return -1;
  }

  int ret;
  struct timeval timeout = {0, 0};

  switch(st->type){
  case PROTOCOL_TCP_UNICAST://TCP
  case PROTOCOL_UDP_MULTICAST://UDP
    fprintf(stderr, "Not reimplemented\n");
    abort();
    break;
  case PROTOCOL_ETHERNET_MULTICAST://ETHERNET
  case PROTOCOL_LOCAL_FILE:
    ret = st->fill_buffer(st, &timeout);
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

long stream_read(struct stream *myStream, char **data, const struct filter *my_Filter){
  int filterStatus=0;
  int skip_counter=-1;
  int ret = 0;

  /* as a precaution, reset the datapoint to NULL so errors will be easier to track down */
  *data = NULL;

  do {
    skip_counter++;

    /* bufferSize tells how much data there is available in the buffer */
    if( myStream->bufferSize == myStream->readPos ){
      if ( (ret=fill_buffer(myStream)) != 0 ){
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
      if ( (ret=fill_buffer(myStream)) != 0 ){
	return ret; /* could not read */
      }

      continue;
    }
    
    /* set next packet and advance the read pointer */
    *data = myStream->buffer + myStream->readPos;
    myStream->readPos += packet_size;

    filterStatus = 1; /* match by default, i.e. if no filter is used. */
    if ( my_Filter ){
      filterStatus = filter_match(my_Filter, cp->payload, cp);
    }
  } while(filterStatus==0);
  
  return 0;
}
