#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "caputils/caputils.h"

static int stream_file_fillbuffer(struct stream* st){
  assert(st);
  assert(st->myFile);

  size_t available = buffLen;
  size_t offset = 0;

  /* copy old content */
  if ( st->readPos > 0 ){
    size_t bytes = st->bufferSize - st->readPos;
    memmove(st->buffer, st->buffer + st->readPos, bytes); /* move content */
    memset(st->buffer + bytes, 0, buffLen-bytes); /* reset rest */
    st->bufferSize = bytes;
    st->readPos = 0;
    available = buffLen - bytes;
    offset = bytes;
  }

  char* dst = st->buffer + offset;
  int readBytes = fread(dst, 1, available, st->myFile);

  /* check if an error occured, EOF is not considered an error. */
  if ( readBytes < available && ferror(st->myFile) > 0 ){
    return -1;
  }

  st->bufferSize += readBytes;
  return readBytes;
}

/**
 * Initialize file stream.
 * @return Non-zero on error (see errno(3) for descriptions).
 */
int stream_file_init(struct stream* st, const char* filename){
  assert(st);

  /* validate that filename is set */
  if ( !filename ){
    return ENOENT;
  }

  /* try to open the file */
  st->myFile = fopen(filename, "rb");
  if( !st->myFile ){
    return errno;
  }

  struct file_header* fhptr = &(st->FH);
  int i;

  /* load stream file header */
  {
    /* try legacy header first */
    struct file_header_05 fhleg;
    fread(&fhleg, 1, sizeof(struct file_header_05), st->myFile);

    if ( fhleg.version.major == 0 && fhleg.version.minor == 5 ){
      /* legacy header matches, copy it */

      fhptr->comment_size = fhleg.comment_size;
      fhptr->version.major = 0;
      fhptr->version.minor = 5;
      memcpy(fhptr->mpid, fhleg.mpid, 200);
    } else {
      /* load new header */
      fseek(st->myFile, 0L, SEEK_SET);
      fread(fhptr, 1, sizeof(struct file_header), st->myFile);
    }
  }

  /* read comment */
  st->comment = (char*)malloc(fhptr->comment_size+1);
  if ( (i = fread(st->comment, 1, fhptr->comment_size, st->myFile)) < fhptr->comment_size ){
    /** @todo need to be able to set more detailed error */
    return EINVAL;
  }
  st->comment[i] = 0; /* the null-terminator might not be included in file */

  if ( !is_valid_version(fhptr) ){ /* is_valid_version has side-effects */
    return EINVAL;
  }

  /** @bug I think this memory leaks */
  st->filename = strdup(filename);
  
  /* add callbacks */
  st->fill_buffer = stream_file_fillbuffer;
  st->destroy = NULL;

  return 0;
}
