#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <caputils/caputils.h>
#include "caputils_int.h"

#include <string.h>

int stream_init(struct stream* st, int protocol, int port){
  st->type=protocol;
  st->myFile=0;
  st->mySocket=0;
  st->expSeqnr = 0;
  st->pktCount = 0;
  st->bufferSize=0;
  st->readPos=0;
  st->flushed = 0;
  st->address=0;
  st->filename=0;
  st->portnr=port;

  st->ifindex=0;
  /** st->if_mtu = 0; for backwards compability, @bug */
  st->comment=0;

  /* callbacks */
  st->fill_buffer = NULL;
  st->destroy = NULL;

  memset(st->buffer, 0, buffLen);

  /* initialize file_header */
  st->FH.comment_size=0;
  memset(st->FH.mpid, 0, 200); /* @bug what is 200? why is not [0] = 0 enought? */

  return 0;
}
