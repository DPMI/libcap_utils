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

#include "caputils/caputils.h"
#include "caputils_int.h"
#include "stream.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum extension_type {
	HEADER_EXT_NONE = 0,
	HEADER_EXT_PADDING = 1,
};

struct file_extension {
	uint16_t type;
	uint16_t next_offset; /* sizeof(header) + sizeof(data) */
};

struct stream_file {
	struct stream base;
	FILE* file;
	int force_flush; /* force stream to be flushed on every write */
};

static int stream_file_fillbuffer(struct stream_file* st, struct timeval* timeout, char* dst, size_t max){
	assert(st);
	assert(st->file);
	assert(st->base.buffer_size);

	size_t readBytes = fread(dst, 1, max, st->file);

	/* check if an error occured, EOF is not considered an error. */
	if ( readBytes < max && ferror(st->file) > 0 ){
		return -1;
	}

	return readBytes;
}

static int stream_file_write(struct stream_file* st, const void* data, size_t size){
	assert(st);
	assert(data);
	assert(size > 0);

	int ret;
	if( (ret=fwrite(data, size, 1, st->file)) != 1 ){
		if ( feof(st->file) ){
			return ENOSPC;
		} else if ( ferror(st->file) ){
			return errno;
		} else {
			fprintf(stderr, "fwrite(%p, %zd, 1, %p[fd:%d]) returned error (ret: %d, errno: %d) but neither feof or ferror set. Dragons ahead!\n", data, size, st->file, fileno(st->file), ret, errno);
			return EINVAL;
		}
	}

	/* make sure the data is flushed */
	if ( __builtin_expect(st->force_flush,0) ){
		fflush(st->file);
		fsync(fileno(st->file));
	}

	return 0;
}

/* Try to load a v05 file header */
static int load_legacy_05(struct file_header_05* fh, FILE* src){
	fseek(src, 0L, SEEK_SET);

	/* silence gcc [-Wunused-result] */
	int __attribute__((unused)) bytes =			\
		fread(fh, 1, sizeof(struct file_header_05), src);

	return fh->version.major == 0 && fh->version.minor == 5;
}

/* Try to load a v06 file header */
static int load_legacy_06(struct file_header_06* fh, FILE* src){
	fseek(src, 0L, SEEK_SET);

	/* silence gcc [-Wunused-result] */
	int __attribute__((unused)) bytes =			\
		fread(fh, 1, sizeof(struct file_header_06), src);

	return fh->version.major == 0 && fh->version.minor == 6;
}

static int need_fclose(const struct stream_file* st){
	return stream_addr_type(&st->base.addr) == STREAM_ADDR_CAPFILE || stream_addr_have_flag(&st->base.addr, STREAM_ADDR_FCLOSE);
}

static long stream_file_destroy(struct stream_file* st){
	if ( stream_addr_have_flag(&st->base.addr, STREAM_ADDR_UNLINK) ){
		unlink(st->base.addr.local_filename);
	}

	if ( need_fclose(st) ){
		fclose(st->file);
	}

	free(st->base.comment);
	free(st);
	return 0;
}

static int stream_file_flush(struct stream_file* st){
	return fflush(st->file);
}

/**
 * Initialize file stream.
 * @return Non-zero on error (see errno(3) for descriptions).
 */
int stream_file_open(struct stream** stptr, FILE* fp, const char* filename, size_t buffer_size){
	assert(stptr);
	*stptr = NULL;
	int ret;

	/* validate that filename or fp is set */
	if ( !(filename||fp) ){
		return ENOENT;
	}

	/* try to open the file */
	if ( !fp ) {
		fp = fopen(filename, "rb");
		if( !fp ){
			return errno;
		}
	}

	/* Use a relative smaller buffer-size by default as it will yield faster
	 * response-times when using pipes. */
	if ( buffer_size == 0 ){
		buffer_size = BUFSIZ; /* BUFSIZ is set to optimal size for this platform */
	}

	/* Initialize the structure */
	if ( (ret = stream_alloc(stptr, PROTOCOL_LOCAL_FILE, sizeof(struct stream_file), buffer_size, BUFSIZ) != 0) ){
		return ret;
	}

	struct stream_file* st = (struct stream_file*)*stptr;
	struct file_header_t* fhptr = &(st->base.FH);
	int i;

	st->base.num_addresses = 1;
	st->file = fp;
	st->force_flush = 0;

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

	/* read extension headers */
	const int have_extensions = fhptr->header_offset > 216;
	if ( have_extensions ){
		do {
			struct file_extension ext;
			if ( fread(&ext, sizeof(struct file_extension), 1, st->file) != 1 ){
				return ERROR_CAPFILE_TRUNCATED;
			}

			if ( ext.type == HEADER_EXT_NONE ){
				/* last extension header */
				break;
			}

			switch ( ext.type ){
			case HEADER_EXT_PADDING:
				/* padding only, just skip bytes */
				break;

			default:
				/* unrecognized extension header, ignored */
				break;
			}

			/* test for invalid offset size (possibly malformed files) */
			const size_t min_size = sizeof(struct file_extension);
			const size_t max_size = fhptr->header_offset;
			if ( ext.next_offset < min_size || ext.next_offset > max_size ){
				return ERROR_CAPFILE_INVALID;
			}

			/* move to next */
			fseek(st->file, ext.next_offset - sizeof(struct file_extension), SEEK_CUR);
		} while (1);
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

	/* add callbacks */
	st->base.fill_buffer = (fill_buffer_callback)stream_file_fillbuffer;
	st->base.destroy = (destroy_callback)stream_file_destroy;
	st->base.write = (write_callback)stream_file_write;
	st->base.flush = (flush_callback)stream_file_flush;

	return 0;
}

int stream_file_create(struct stream** stptr, FILE* fp, const char* filename, const char* mpid, const char* comment, int flags){
	assert(stptr);
	*stptr = NULL;
	int ret = 0;

	/* validate that filename is set */
	if ( !(filename||fp) ){
		return ENOENT;
	}

	/* try to open the file */
	if ( !fp ){
		fp = fopen(filename, "wb");
		if( !fp ){
			return errno;
		}
	}

	/* sanitize comment */
	if ( !comment ){
		comment = "";
	}

	/* Initialize the structure */
	if ( (ret = stream_alloc(stptr, PROTOCOL_LOCAL_FILE, sizeof(struct stream_file), 0, BUFSIZ) != 0) ){
		return ret;
	}

	struct stream_file* st = (struct stream_file*)*stptr;

	st->file = fp;
	st->force_flush = flags & STREAM_ADDR_FLUSH;

	st->base.num_addresses = 1;
	st->base.comment = strdup(comment);
	st->base.FH.magic = CAPUTILS_FILE_MAGIC;
	st->base.FH.version.major = VERSION_MAJOR;
	st->base.FH.version.minor = VERSION_MINOR;
	st->base.FH.header_offset = sizeof(struct file_header_t);
	st->base.FH.comment_size = strlen(comment);
	//strncpy(st->base.FH.mpid, mpid, 200); /* Old */

	memset(st->base.FH.mpid, 0, sizeof st->base.FH.mpid);  // fill with zeros
	if (mpid) {
    	size_t cap = sizeof st->base.FH.mpid - 1;          // leave room for '\0'
    	size_t n = strnlen(mpid, cap);                     // copy at most cap bytes
    	memcpy(st->base.FH.mpid, mpid, n);                 // copy n bytes
    	/* NUL is already present due to memset; explicit write optional:
    	   st->base.FH.mpid[n] = '\0'; */
	}



	if ( fwrite(&st->base.FH, 1, sizeof(struct file_header_t), st->file) < sizeof(struct file_header_t) ){
		return EIO;
	}

	if ( fwrite(comment, 1, strlen(comment), st->file) < strlen(comment) ){
		return EIO;
	}

	/* add callbacks */
	st->base.fill_buffer = (fill_buffer_callback)stream_file_fillbuffer;
	st->base.destroy = (destroy_callback)stream_file_destroy;
	st->base.write = (write_callback)stream_file_write;
	st->base.flush = (flush_callback)stream_file_flush;

	return 0;
}
