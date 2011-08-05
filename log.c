#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "caputils/log.h"
#include <ctype.h>
#include <time.h>
#include <sys/time.h>

int vlogmsg(FILE* fp, const char* tag, const char* fmt, va_list ap){
  struct timeval tid1;
  gettimeofday(&tid1,NULL);

  struct tm *dagtid;  
  dagtid=localtime(&tid1.tv_sec);

  char time[20] = {0,};  
  strftime(time, sizeof(time), "%Y-%m-%d %H.%M.%S", dagtid);
  
  fprintf(fp, "[%s] [%8s ] ", time, tag);
  return vfprintf(fp, fmt, ap);
}

int logmsg(FILE* fp, const char* tag, const char* fmt, ...){
  va_list ap;
  va_start(ap, fmt);
  int ret = vlogmsg(fp, tag, fmt, ap);
  va_end(ap);
  return ret;
}

void hexdump(FILE* fp, const char* data, size_t size){
  const size_t align = size + (size % 16);
  fputs("[0000]  ", fp);
  for( unsigned int i=0; i < align; i++){
    if ( i < size ){
      fprintf(fp, "%02X ", data[i] & 0xff);
    } else {
      fputs("   ", fp);
    }
    if ( i % 4 == 3 ){
      fputs("   ", fp);
    }
    if ( i % 16 == 15 ){
      fputs("    |", fp);
      for ( unsigned int j = i-15; j<=i; j++ ){
        char ch = data[j];
	
        if ( j >= size ){
          ch = ' ';
        } else if ( !isprint(data[j]) ){
          ch = '.';
        }
	
        fputc(ch, fp);
      }
      fputs("|", fp);
      if ( (i+1) < align){
        fprintf(fp, "\n[%04X]  ", i+1);
      }
    }
  }
  fprintf(fp, "\n");
}
