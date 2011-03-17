ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libcap_utils.la
nobase_include_HEADERS = \
	caputils/caputils.h \
	caputils/stream.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = cap_utils.pc

libcap_utils_la_LDFLAGS = -shared -version-info 0:0:0
libcap_utils_la_CFLAGS = -Wall
libcap_utils_la_SOURCES = \
	closestream.c \
	createfilter.c \
	createstream.c \
	ethaton.c \
	filter.c \
	openstream.c \
	readpost.c \
	spectopico.c \
	stream_ethernet.c \
	stream_file.c \
	stream_udp.c \
	stream_tcp.c \
	timecmp.c \
	valtopico.c \
	writepost.c
