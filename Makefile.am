ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libcap_utils.la
bin_PROGRAMS = capinfo

nobase_include_HEADERS = \
	caputils/caputils.h \
	caputils/stream.h \
	caputils/version.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = cap_utils.pc

libcap_utils_la_LDFLAGS = -shared -version-info 0:1:0
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
	stream.c \
	stream_ethernet.c \
	stream_file.c \
	stream_udp.c \
	stream_tcp.c \
	timecmp.c \
	valtopico.c \
	writepost.c

capinfo_CFLAGS = -Wall
capinfo_LDADD = libcap_utils.la