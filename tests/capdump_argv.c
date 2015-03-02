#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "caputils/stream.h"
#include "caputils/utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>

static int check(const char* cmdline, int expect_fail){
	int ret;

	/* try to execute */
	ret = system(cmdline);
	if ( ret != 0 && !expect_fail ){
		fprintf(stderr, "capdump_argv: command exited with code %d: \"%s\"\n", WEXITSTATUS(ret), cmdline);
		return 0;
	} else if ( ret == 0 && expect_fail ){
		fprintf(stderr, "capdump_argv: command exited with code 0 but expected to fail: \"%s\"\n", cmdline);
		return 0;
	} else if ( ret != 0 && expect_fail ){
		return 1;
	}

	stream_t st;
	stream_addr_t addr;
	stream_addr_str(&addr, "test-temp.cap", 0);

	/* validate output */
	if ( (ret=stream_open(&st, &addr, NULL, 0)) != 0 ){
		fprintf(stderr, "capdump_argv: command did not create a valid trace: \"%s\"\n", cmdline);
		fprintf(stderr, "capdump_argv: stream_open(..) returned %d: %s\n", ret, caputils_error_string(ret));
		return 0;
	}

	caphead_t cp;
	while ( stream_read(st, &cp, NULL, NULL) == 0 ); /* do nothing */

	const stream_stat_t* stat = stream_get_stat(st);
	if ( stat->read != 1 ){
		fprintf(stderr, "capdump_argv: command created and incorrect trace: \"%s\"\n", cmdline);
		fprintf(stderr, "capdump_argv: expected 1 packet, got %"PRIu64".\n", stat->read);
		stream_close(st);
		unlink("test-temp.cap");
		return 0;
	}
	stream_close(st);
	unlink("test-temp.cap");

	return 1;
}

int main(int argc, const char* argv[]){
	return 1
		&& check("./capdump "TOP_SRCDIR"/tests/single.cap test-temp.cap 2> /dev/null", 0)
		&& check("./capdump "TOP_SRCDIR"/tests/single.cap -o test-temp.cap 2> /dev/null", 0)
		&& check("./capdump "TOP_SRCDIR"/tests/single.cap > test-temp.cap 2> /dev/null", 0)
		&& check("cat "TOP_SRCDIR"/tests/single.cap | ./capdump test-temp.cap 2> /dev/null", 0)
		&& check("cat "TOP_SRCDIR"/tests/single.cap | ./capdump -o test-temp.cap 2> /dev/null", 0)
		&& check("cat "TOP_SRCDIR"/tests/single.cap | ./capdump > test-temp.cap 2> /dev/null", 0)
		&& check("./capdump > test-temp.cap 2> /dev/null", 1)
		&& check("./capdump "TOP_SRCDIR"/tests/single.cap 2> /dev/null", 1)
		== 1 ? 0 : 1;
}
