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

#include "caputils/log.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static void write_time(FILE* fp){
	struct timeval tid1;
	gettimeofday(&tid1,NULL);

	struct tm *dagtid;
	dagtid=localtime(&tid1.tv_sec);

	char time[20] = {0,};
	strftime(time, sizeof(time), "%Y-%m-%d %H.%M.%S", dagtid);
	fprintf(fp, "[%s] ", time);
}

static void write_tag(FILE* fp, const char* tag){
	static const size_t tag_width = 7;
	const size_t len = strlen(tag);
	// make sure that we dont have negative diff, would make half very large...
	const size_t diff = (tag_width - len) > 0 ? (tag_width - len) : 0 ;
	const size_t half = diff >> 1; /* divide by 2 */
	fputc('[', fp);
	{ /* left padding (adding remainder here, so the sum of padding and tag is tag_width) */
		int n = half + (diff&1); /* since it is a division the LSB will decide the remainder */
		while ( n --> 0 ) fputc(' ', fp);
	}
	fputs(tag, fp);
	{ /* right padding */
		int n = half;
		while ( n --> 0 ) fputc(' ', fp);
	}
	fputc(']', fp);
	fputc(' ', fp);
}

int vlogmsg(FILE* fp, const char* tag, const char* fmt, va_list ap){
	pthread_mutex_lock(&mutex);
	write_time(fp);
	write_tag(fp, tag); /* centered */
	int ret = vfprintf(fp, fmt, ap);
	pthread_mutex_unlock(&mutex);
	return ret;
}

int logmsg(FILE* fp, const char* tag, const char* fmt, ...){
	va_list ap;
	va_start(ap, fmt);
	int ret = vlogmsg(fp, tag, fmt, ap);
	va_end(ap);
	return ret;
}

void hexdump(FILE* dst, const char* data, size_t size){
	char* tmp = hexdump_str(data, size);
	fputs(tmp, dst);
	free(tmp);
}

char* hexdump_str(const char* data, size_t size){
	char* buffer = malloc(size*10+80); /* more than really needed */
	char* dst = buffer;

	const size_t align = size + (size % 16);
	dst += sprintf(dst, "[0000]  ");
	for( unsigned int i=0; i < align; i++){
		if ( i < size ){
			dst += sprintf(dst, "%02X ", data[i] & 0xff);
		} else {
			dst += sprintf(dst, "   ");
		}
		if ( i % 4 == 3 ){
			dst += sprintf(dst, "  ");
		}
		if ( i % 16 == 15 ){
			dst += sprintf(dst, "    |");
			for ( unsigned int j = i-15; j<=i; j++ ){
				char ch = data[j];

				if ( j >= size ){
					ch = ' ';
				} else if ( !isprint(data[j]) ){
					ch = '.';
				}

				dst += sprintf(dst, "%c", ch);
			}
			dst += sprintf(dst, "|");
			if ( (i+1) < align){
				dst += sprintf(dst, "\n[%04X]  ", i+1);
			}
		}
	}
	dst += sprintf(dst, "\n");

	return buffer;
}
