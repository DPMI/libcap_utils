#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <caputils/caputils.h>
#include "caputils_int.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

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
