ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libcap_utils.la
nobase_include_HEADERS = cap_utils.h

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
	timecmp.c \
	valtopico.c \
	writepost.c
