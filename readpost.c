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
#include "caputils/caputils.h"
#include "caputils_int.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>

int fill_buffer(struct stream* st){
#ifdef DEBUG
  fprintf(stderr, "Filling packet buffer.\n");
#endif /* DEBUG */

  if( st->flushed==1 ){
    fprintf(stderr, "EOF stream reached.\n");
    return(0);
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
    ret = st->fill_buffer(st);
    if ( ret > 0 ){ /* common case */
      return 1;
    } else if ( ret < 0 ){ /* failed to read */
      fprintf(stderr, "Failed to read from stream: %s", strerror(errno));
      return 0;
    } else if ( ret == 0 ){ /* EOF, TCP shutdown etc */
      return 0;
    }
    break;
  }
  
  /* not reached */
  return 1;
}

int read_post(struct stream *myStream, char **data, const struct filter *my_Filter){
  int filterStatus=0;
  int skip_counter=-1;

  /* as a precaution, reset the datapoint to NULL so errors will be easier to track down */
  *data = NULL;

  do {
    skip_counter++;

    /* bufferSize tells how much data there is available in the buffer */
    if( myStream->bufferSize == myStream->readPos ){
      if ( fill_buffer(myStream) == 0 ){
	return 0; /* could not read */
      }
      continue;
    }

    // We have some data in the buffer.
    struct cap_header* cp = (struct cap_header*)(myStream->buffer + myStream->readPos);
#ifdef DEBUG
    fprintf(stderr, "readPos = %d \t cp->nic: %s, cp->caplen: %d,  cp->len: %d\n", myStream->readPos, cp->nic, cp->caplen, cp->len);
#endif /* DEBUG */

    const size_t packet_size = sizeof(struct cap_header) + cp->caplen;
    const size_t start_pos = myStream->readPos;
    const size_t end_pos = start_pos + packet_size;

    assert(cp->caplen > 0);
    assert(packet_size > 0);

    if( end_pos > myStream->bufferSize ) {
#ifdef DEBUG
      fprintf(stderr, "Insufficient data.\n");
#endif /* DEBUG */
      if ( fill_buffer(myStream) == 0 ){
	return 0; /* could not read */
      }

      continue;
    }
    
    /* set next packet and advance the read pointer */
    *data = myStream->buffer + myStream->readPos;
    myStream->readPos += packet_size;

    filterStatus = checkFilter((myStream->buffer+myStream->readPos), my_Filter);
    //    printf("[%d]", skip_counter);
  } while(filterStatus==0);
  //  printf("Skipped %d packets.\n",skip_counter);
  
  return(1);
}
