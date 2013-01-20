#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "caputils/interface.h"
#include "caputils/utils.h"
#include <stdio.h>
#include <string.h>

const char* bool(int x){ return x ? "yes" : "no"; }

int main(int argc, const char* argv[]){
	struct iface iface;
	int ret;

	if ( (ret=iface_get(argv[1], &iface)) != 0 ){
		fprintf(stderr, "ifstat: %s\n", strerror(ret));
		return 1;
	}

	fprintf(stdout, "     if_name: %s\n", iface.if_name);
	fprintf(stdout, "   if_hwaddr: %s\n", hexdump_address(&iface.if_hwaddr));
	fprintf(stdout, "    if_index: %d\n", iface.if_index);
	fprintf(stdout, "      if_mtu: %d\n", iface.if_mtu);
	fprintf(stdout, "       if_up: %s\n", bool(iface.if_up));
	fprintf(stdout, " if_loopback: %s\n", bool(iface.if_loopback));
	fprintf(stdout, "if_multicast: %s\n", bool(iface.if_multicast));

	return 0;
}
