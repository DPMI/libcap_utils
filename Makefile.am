ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libcap_utils.la libcap_filter.la libcap_stream.la
bin_PROGRAMS = 
man1_MANS =
man3_MANS = \
	man/libcaputils.3 \
	man/libcap_filter.3 \
	man/stream_read.3

if BUILD_CAPINFO
bin_PROGRAMS += capinfo
endif

if BUILD_CAPDUMP
bin_PROGRAMS += capdump
endif

if BUILD_CAPFILTER
bin_PROGRAMS += capfilter
man1_MANS += man/capfilter.1
endif

notrans_dist_man_MANS =     \
	man/libcaputils.3   \
	man/libcap_filter.3 \
	man/stream_read.3   \
	man/capfilter.1

TESTS = tests/filter_argv tests/address
check_PROGRAMS = ${TESTS}

nobase_include_HEADERS =    \
	caputils/address.h  \
	caputils/picotime.h \
	caputils/file.h     \
	caputils/utils.h    \
	caputils/capture.h  \
	caputils/filter.h   \
	caputils/caputils.h \
	caputils/stream.h   \
	caputils/version.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = cap_stream.pc cap_filter.pc

libcap_stream_la_LDFLAGS = -version-info 0:0:0
libcap_stream_la_CFLAGS = -Wall
libcap_stream_la_LIBADD = libcap_utils.la libcap_filter.la
libcap_stream_la_SOURCES =  \
	stream.c stream.h   \
	stream_ethernet.c   \
	stream_file.c

libcap_utils_la_LDFLAGS = -version-info 2:0:0
libcap_utils_la_CFLAGS = -Wall
libcap_utils_la_SOURCES =   \
	caputils_int.h      \
	address.c           \
	error.c             \
	utils.c             \
	picotime.c

#	stream_udp.c \
#	stream_tcp.c \
#

libcap_filter_la_LDFLAGS = -version-info 0:0:0
libcap_filter_la_CFLAGS = -Wall
libcap_filter_la_LIBADD = libcap_utils.la
libcap_filter_la_SOURCES = createfilter.c filter.c

capinfo_CFLAGS = -Wall
capinfo_LDADD = libcap_utils.la libcap_filter.la libcap_stream.la

capdump_CFLAGS = -Wall
capdump_LDADD = libcap_utils.la libcap_filter.la libcap_stream.la

capfilter_CFLAGS = -Wall
capfilter_LDADD = libcap_filter.la libcap_utils.la

tests_filter_argv_CXXFLAGS = -Wall $(CPPUNIT_CFLAGS)
tests_filter_argv_LDFLAGS = $(CPPUNIT_LIBS)
tests_filter_argv_LDADD = libcap_filter.la libcap_utils.la
tests_filter_argv_SOURCES = tests/filter_argv.cpp

tests_address_CXXFLAGS = -Wall $(CPPUNIT_CFLAGS)
tests_address_LDFLAGS = $(CPPUNIT_LIBS)
tests_address_LDADD = libcap_utils.la
tests_address_SOURCES = tests/address.cpp
