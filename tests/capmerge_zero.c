#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

int main(int argc, const char* argv[]){
	return system("./capmerge -qs "TOP_SRCDIR"/tests/empty.cap -o /dev/null > /dev/null") == 0 ? 0 : 1;
}
