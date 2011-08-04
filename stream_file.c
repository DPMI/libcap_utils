#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "caputils/caputils.h"
#include "caputils_int.h"
#include "stream.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct stream_file {
  struct stream base;
  FILE* file;
  const char* filename;
};

static int stream_file_fillbuffer(struct stream_file* st){
  assert(st);
  assert(st->file);

  size_t available = buffLen;
  size_t offset = 0;

  /* copy old content */
  if ( st->base.readPos > 0 ){
    size_t bytes = st->base.bufferSize - st->base.readPos;
    memmove(st->base.buffer, st->base.buffer + st->base.readPos, bytes); /* move content */
    memset(st->base.buffer + bytes, 0, buffLen-bytes); /* reset rest */
    st->base.bufferSize = bytes;
    st->base.readPos = 0;
    available = buffLen - bytes;
    offset = bytes;
  }

  char* dst = st->base.buffer + offset;
  size_t readBytes = fread(dst, 1, available, st->file);

  /* check if an error occured, EOF is not considered an error. */
  if ( readBytes < available && ferror(st->file) > 0 ){
    return -1;
  }

  st->base.bufferSize += readBytes;
  return readBytes;
}

static int write(struct stream_file* st, const void* data, size_t size){
  if( fwrite(data, 1, size, st->file) != size ){
    return errno; /* @bug must check with feof(3) and ferror(3) */
  }
  return 0;
}

/* Try to load a v05 file header */
int load_legacy_05(struct file_header_05* fh, FILE* src){
  fseek(src, 0L, SEEK_SET);

  /* silence gcc [-Wunused-result] */
  int __attribute__((unused)) bytes =			\
    fread(fh, 1, sizeof(struct file_header_05), src);
  
  return fh->version.major == 0 && fh->version.minor == 5;
}

/* Try to load a v06 file header */
int load_legacy_06(struct file_header_06* fh, FILE* src){
  fseek(src, 0L, SEEK_SET);

  /* silence gcc [-Wunused-result] */
  int __attribute__((unused)) bytes =			\
    fread(fh, 1, sizeof(struct file_header_06), src);

  return fh->version.major == 0 && fh->version.minor == 6;
}

/**
 * Initialize file stream.
 * @return Non-zero on error (see errno(3) for descriptions).
 */
int stream_file_open(struct stream** stptr, const char* filename){
  assert(stptr);
  *stptr = NULL;
  int ret = 0;

  /* validate that filename is set */
  if ( !filename ){
    return ENOENT;
  }

  /* try to open the file */
  FILE* fp = fopen(filename, "rb");
  if( !fp ){
    return errno;
  }

  /* Initialize the structure */
  if ( (ret = stream_alloc(stptr, PROTOCOL_LOCAL_FILE, sizeof(struct stream_file)) != 0) ){
    return ret;
  }
  
  struct stream_file* st = (struct stream_file*)*stptr;
  struct file_header_t* fhptr = &(st->base.FH);
  int i;

  st->file = fp;

  /* load stream file header */
  size_t bytes = fread(fhptr, 1, sizeof(struct file_header_t), st->file);
  if ( bytes < sizeof(struct file_header_t) ){ /* even if this struct is larger */
    return ERROR_CAPFILE_INVALID;            /* than legacy, the file would be */
                                             /* to small to be anything useful anyway. */
  }

  if ( fhptr->magic != CAPUTILS_FILE_MAGIC ){
    /* try loading legacy headers */

    struct file_header_05 fhleg05;
    struct file_header_06 fhleg06;

    if ( load_legacy_05(&fhleg05, st->file) ){
      fhptr->comment_size = fhleg05.comment_size;
      fhptr->version.major = 0;
      fhptr->version.minor = 5;
      fhptr->header_offset = sizeof(struct file_header_05);
      memcpy(fhptr->mpid, fhleg05.mpid, 200);
    } else if ( load_legacy_06(&fhleg06, st->file) ){
      fhptr->comment_size = fhleg06.comment_size;
      fhptr->version.major = 0;
      fhptr->version.minor = 6;
      fhptr->header_offset = sizeof(struct file_header_06);
      memcpy(fhptr->mpid, fhleg06.mpid, 200);
    } else {
      return ERROR_CAPFILE_INVALID;
    }
  }

  fseek(st->file, fhptr->header_offset, SEEK_SET);

  /* read comment */
  st->base.comment = (char*)malloc(fhptr->comment_size+1);
  if ( (i = fread(st->base.comment, 1, fhptr->comment_size, st->file)) < fhptr->comment_size ){
    /** @todo need to be able to set more detailed error */
    return ERROR_CAPFILE_TRUNCATED;
  }
  st->base.comment[i] = 0; /* the null-terminator might not be included in file */

  if ( !is_valid_version(fhptr) ){ /* is_valid_version has side-effects */
    return EINVAL;
  }

  st->filename = strdup(filename);
  
  /* add callbacks */
  st->base.fill_buffer = (fill_buffer_callback)stream_file_fillbuffer;
  st->base.destroy = NULL;
  st->base.write = (write_callback)write;

  return 0;
}

int stream_file_create(struct stream** stptr, FILE* fp, const char* filename, const char* mpid, const char* comment){
  assert(stptr);
  *stptr = NULL;
  int ret = 0;

  /* validate that filename is set */
  if ( !filename ){
    return ENOENT;
  }

  /* try to open the file */
  if ( !fp ){
    fp = fopen(filename, "wb");
    if( !fp ){
      return errno;
    }
  }

  /* Initialize the structure */
  if ( (ret = stream_alloc(stptr, PROTOCOL_LOCAL_FILE, sizeof(struct stream_file)) != 0) ){
    return ret;
  }

  struct stream_file* st = (struct stream_file*)*stptr;
  
  st->file = fp;
  st->filename = strdup(filename);

  st->base.comment = strdup(comment);
  st->base.FH.magic = CAPUTILS_FILE_MAGIC;
  st->base.FH.version.major = VERSION_MAJOR;
  st->base.FH.version.minor = VERSION_MINOR;
  st->base.FH.header_offset = sizeof(struct file_header_t);
  st->base.FH.comment_size = strlen(comment);
  strncpy(st->base.FH.mpid, mpid, 200);

  if ( fwrite(&st->base.FH, 1, sizeof(struct file_header_t), st->file) < sizeof(struct file_header_t) ){
    return EIO;
  }

  if ( fwrite(comment, 1, strlen(comment), st->file) < strlen(comment) ){
    return EIO;
  }

  /* add callbacks */
  st->base.fill_buffer = (fill_buffer_callback)stream_file_fillbuffer;
  st->base.destroy = NULL;
  st->base.write = (write_callback)write;

  return 0;
}
