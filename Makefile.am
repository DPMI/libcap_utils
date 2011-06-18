ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libcap_utils.la libcap_filter.la
bin_PROGRAMS = capinfo

nobase_include_HEADERS =    \
	caputils/picotime.h \
	caputils/file.h     \
	caputils/utils.h    \
	caputils/capture.h  \
	caputils/filter.h   \
	caputils/caputils.h \
	caputils/stream.h   \
	caputils/version.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = cap_utils.pc cap_filter.pc

libcap_utils_la_LDFLAGS = -version-info 1:0:0
libcap_utils_la_CFLAGS = -Wall
libcap_utils_la_SOURCES = \
	caputils_int.h \
	closestream.c \
	createstream.c \
	error.c \
	ethaton.c \
	openstream.c \
	picotime.c \
	readpost.c \
	stream.c \
	stream_ethernet.c \
	stream_file.c \
	writepost.c

#	stream_udp.c \
#	stream_tcp.c \
#

libcap_filter_la_LDFLAGS = -version-info 0:0:0
libcap_filter_la_CFLAGS = -Wall
libcap_filter_la_SOURCES = createfilter.c filter.c

capinfo_CFLAGS = -Wall
capinfo_LDADD = libcap_utils.la libcap_filter.la
