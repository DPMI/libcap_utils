#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <caputils/caputils.h>
#include "caputils_int.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

int stream_alloc(struct stream** stptr, enum protocol_t protocol, size_t size){
  assert(stptr);

  /* the buffer is always placed after the struct */
  struct stream* st = (struct stream*)malloc(size + buffLen);
  *stptr = st;

  st->type = protocol;
  st->comment = NULL;
  st->buffer = (char*)st + size; /* calculate pointer to buffer */

  st->expSeqnr = 0;
  st->pktCount = 0;
  st->bufferSize=0;
  st->readPos=0;
  st->flushed = 0;

  /* callbacks */
  st->fill_buffer = NULL;
  st->destroy = NULL;

  memset(st->buffer, 0, buffLen);

  /* initialize file_header */
  st->FH.comment_size = 0;
  memset(st->FH.mpid, 0, 200); /* @bug what is 200? why is not [0] = 0 enought? */

  return 0;
}

void match_inc_seqnr(struct stream* restrict st, const struct sendhead* restrict sh){
    /* validate sequence number */
    if( st->expSeqnr != ntohl(sh->sequencenr) ){
      fprintf(stderr,"Missmatch of sequence numbers. Expeced %ld got %d\n", st->expSeqnr, ntohl(sh->sequencenr));
      st->expSeqnr = ntohl(sh->sequencenr); /* reset sequence number */
    }

    /* increment sequence number (next packet is expected to have +1) */
    st->expSeqnr++;

    /* wrap sequence number */
    if( st->expSeqnr>=0xFFFF ){
      st->expSeqnr=0;
    }
}
