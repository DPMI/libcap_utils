ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -Wall ${PCAP_CFLAGS} ${PFRING_CFLAGS}

lib_LTLIBRARIES = libcap_utils-07.la libcap_filter-07.la libcap_stream-07.la libcap_marc-07.la
bin_PROGRAMS = 
noinst_PROGRAMS = ifstat
man1_MANS =
man3_MANS =                 \
	man/libcaputils_reading.3 \
	man/libcap_filter.3       \
	man/stream-address.3      \
	man/stream_add.3          \
	man/stream_close.3        \
	man/stream_from_getopt.3  \
	man/stream_open.3         \
	man/stream_peek.3         \
	man/stream_read.3
notrans_dist_man_MANS =     \
	man/libcaputils_reading.3 \
	man/libcap_filter.3       \
	man/stream-address.3      \
	man/stream_add.3          \
	man/stream_close.3        \
	man/stream_from_getopt.3  \
	man/stream_open.3         \
	man/stream_peek.3         \
	man/stream_read.3

EXTRA_DIST =
CLEANFILES =

if BUILD_PCAP
bin_PROGRAMS += pcap2cap cap2pcap
endif

if BUILD_CAPINFO
bin_PROGRAMS += capinfo
endif

if BUILD_CAPDUMP
bin_PROGRAMS += capdump
man1_MANS += man/capdump.1
notrans_dist_man_MANS += man/capdump.1
endif

if BUILD_CAPFILTER
bin_PROGRAMS += capfilter
man1_MANS += man/capfilter.1
notrans_dist_man_MANS += man/capfilter.1
endif

if BUILD_CAPMARKER
bin_PROGRAMS += capmarker
man1_MANS += man/capmarker.1
notrans_dist_man_MANS += man/capmarker.1
endif

if BUILD_CAPMERGE
bin_PROGRAMS += capmerge
man1_MANS += man/capmerge.1
notrans_dist_man_MANS += man/capmerge.1
endif

if BUILD_CAPSHOW
bin_PROGRAMS += capshow
man1_MANS += man/capshow.1
notrans_dist_man_MANS += man/capshow.1
endif

COMPILED_TESTS = tests/capdump_argv tests/capinfo_zero tests/capmerge_zero
if BUILD_TESTS
# tests which requires cppunit
COMPILED_TESTS += tests/filter_argv tests/address tests/endian tests/packet tests/stream tests/timepico
endif

check_PROGRAMS = ${COMPILED_TESTS}
TESTS = ${COMPILED_TESTS} tests/regressions/issue007_tcp_options.sh

EXTRA_DIST += tests/http.packet tests/single.cap tests/empty.cap tests/regressions/issue007_tcp_options.sh tests/traces/t2.cap
CLEANFILES += test-temp.cap

nobase_include_HEADERS =    \
	caputils/address.h   \
	caputils/capture.h   \
	caputils/caputils.h  \
	caputils/file.h      \
	caputils/filter.h    \
	caputils/interface.h \
	caputils/log.h       \
	caputils/marc.h      \
	caputils/marc_dstat.h\
	caputils/marker.h    \
	caputils/packet.h    \
	caputils/picotime.h  \
	caputils/send.h      \
	caputils/stream.h    \
	caputils/utils.h     \
	caputils/version.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcap_stream-0.7.pc libcap_filter-0.7.pc libcap_utils-0.7.pc libcap_marc-0.7.pc

libcap_stream_07_la_LDFLAGS = -version-info 2:1:2 ${PFRING_LIBS}
libcap_stream_07_la_SOURCES = src/stream.c src/stream.h src/stream_buffer.c src/stream_buffer.h src/stream_file.c src/stream_udp.c

if BUILD_PFRING
libcap_stream_07_la_SOURCES += src/stream_pfring.c
else
libcap_stream_07_la_SOURCES += src/stream_ethernet.c
endif

libcap_utils_07_la_CFLAGS = ${AM_CFLAGS} -I${top_srcdir}/fallback
libcap_utils_07_la_LDFLAGS = -version-info 1:0:1 -Wl,--allow-shlib-undefined
libcap_utils_07_la_SOURCES =   \
	src/caputils_int.h      \
	src/address.c           \
	src/error.c             \
	src/format/arp.c        \
	src/format/dns.c        \
	src/format/ethernet.c   \
	src/format/format.h     \
	src/format/gre.c        \
	src/format/http.c       \
	src/format/icmp.c       \
	src/format/ip.c         \
	src/format/ipv4.c       \
	src/format/ipv6.c       \
	src/format/mp.c         \
	src/format/mpls.c       \
	src/format/tcp.c        \
	src/format/udp.c        \
	src/format.c            \
	src/interface.c         \
	src/log.c               \
	src/marker.c            \
	src/utils.c             \
	src/packet.c            \
	src/picotime.c
#	stream_tcp.c

if BUILD_BE64TOH
libcap_utils_07_la_SOURCES += fallback/be64toh.c fallback/be64toh.h
libcap_utils_07_la_LDFLAGS += -Wl,-defsym=be64toh=_int_be64toh -Wl,-defsym=htobe64=_int_htobe64
endif

BUILT_SOURCES = vcs.h
CLEANFILES += vcs.h
if HAVE_VCS
.PHONY: .vcs
BUILT_SOURCES += .vcs vcs.h stamp-vcs
CLEANFILES += .vcs stamp-vcs
.vcs: Makefile
	@git rev-parse --short HEAD | sed 's/\(.*\)/#define VCS_REV "\1"/' > .vcs
	@git rev-parse --abbrev-ref HEAD | sed 's/\(.*\)/#define VCS_BRANCH "\1"/' >> .vcs
	@cmp -s vcs.h .vcs || touch stamp-vcs
stamp-vcs: .vcs
vcs.h: stamp-vcs
	$(AM_V_GEN)cp .vcs vcs.h
else
vcs.h: Makefile
	@echo -n > vcs.h
endif
libcap_utils_07_la_SOURCES += vcs.h

libcap_filter_07_la_LDFLAGS = -version-info 0:2:0
libcap_filter_07_la_LIBADD = ${PCAP_LIBS}
libcap_filter_07_la_SOURCES = src/createfilter.c src/filter.c

libcap_marc_07_la_LDFLAGS = -shared -version-info 0:1:0
libcap_marc_07_la_CFLAGS = ${AM_CFLAGS} ${libcap_filter_CFLAGS}
libcap_marc_07_la_SOURCES = src/marc.c src/marc_dstat.c

tools_CFLAGS = ${AM_CFLAGS} -I${top_srcdir}/fallback
tools_LIBS = libcap_utils-07.la libcap_filter-07.la libcap_stream-07.la ${PCAP_LIBS}

pcap2cap_SOURCES = tools/pcap2cap.c
pcap2cap_CFLAGS = ${tools_CFLAGS}
pcap2cap_LDADD = ${tools_LIBS}
cap2pcap_SOURCES = tools/cap2pcap.c
cap2pcap_CFLAGS = ${tools_CFLAGS}
cap2pcap_LDADD = ${tools_LIBS}
capinfo_SOURCES = tools/capinfo.c
capinfo_CFLAGS = ${tools_CFLAGS}
capinfo_LDADD = ${tools_LIBS}
capdump_SOURCES = tools/capdump.c
capdump_CFLAGS = ${tools_CFLAGS}
capdump_LDADD = ${tools_LIBS}
capdump_LDFLAGS = -pthread
capfilter_SOURCES = tools/capfilter.c
capfilter_CFLAGS = ${tools_CFLAGS}
capfilter_LDADD = ${tools_LIBS}
capmarker_SOURCES = tools/capmarker.c
capmarker_CFLAGS = ${tools_CFLAGS}
capmarker_LDADD = libcap_utils-07.la libcap_filter-07.la
capmerge_SOURCES = tools/capmerge.c
capmerge_CFLAGS = ${tools_CFLAGS}
capmerge_LDADD = ${tools_LIBS}
capshow_SOURCES = tools/capshow.c
capshow_CFLAGS = ${tools_CFLAGS}
capshow_LDADD = ${tools_LIBS}
ifstat_SOURCES = tools/ifstat.c
ifstat_CFLAGS = ${tools_CFLAGS}
ifstat_LDADD = ${tools_LIBS}

tests_filter_argv_CXXFLAGS = ${AM_CFLAGS} $(CPPUNIT_CFLAGS)
tests_filter_argv_LDFLAGS = $(CPPUNIT_LIBS)
tests_filter_argv_LDADD = libcap_filter-07.la libcap_utils-07.la
tests_filter_argv_SOURCES = tests/filter_argv.cpp

tests_address_CXXFLAGS = ${AM_CFLAGS} $(CPPUNIT_CFLAGS)
tests_address_LDFLAGS = $(CPPUNIT_LIBS)
tests_address_LDADD = libcap_utils-07.la libcap_filter-07.la
tests_address_SOURCES = tests/address.cpp

# -Dfulhack is needed so libtool will become less confused about
# multiple objects of be64toh. By having different cflags it will
# rename the files.
tests_endian_CFLAGS = ${AM_CFLAGS} -Dfulhack
tests_endian_CXXFLAGS = ${AM_CFLAGS} $(CPPUNIT_CFLAGS) -I${top_srcdir}/fallback
tests_endian_LDFLAGS = $(CPPUNIT_LIBS)
tests_endian_LDADD = libcap_utils-07.la libcap_filter-07.la
tests_endian_SOURCES = tests/endian.cpp fallback/be64toh.c

tests_packet_CXXFLAGS = ${AM_CFLAGS} $(CPPUNIT_CFLAGS)
tests_packet_LDFLAGS = $(CPPUNIT_LIBS)
tests_packet_LDADD = libcap_utils-07.la libcap_filter-07.la libcap_stream-07.la
tests_packet_SOURCES = tests/packet.cpp

tests_stream_CXXFLAGS = ${AM_CFLAGS} $(CPPUNIT_CFLAGS)
tests_stream_LDFLAGS = $(CPPUNIT_LIBS)
tests_stream_LDADD = libcap_utils-07.la libcap_stream-07.la libcap_filter-07.la
tests_stream_SOURCES = tests/stream.cpp

tests_timepico_CXXFLAGS = ${AM_CFLAGS} $(CPPUNIT_CFLAGS)
tests_timepico_LDFLAGS = $(CPPUNIT_LIBS)
tests_timepico_LDADD = libcap_utils-07.la libcap_filter-07.la
tests_timepico_SOURCES = tests/timepico.cpp

tests_capdump_argv_LDADD = libcap_utils-07.la libcap_stream-07.la libcap_filter-07.la

install-dumper:
	install -D -m 0755 dist/dumper_init $(DESTDIR)${sysconfdir}/init.d/dumper
	install -D -m 0755 ${top_srcdir}/dist/dumper.sh $(DESTDIR)${bindir}/dumper
	install -D -m 0644 ${top_srcdir}/dist/dumper_conf.sh $(DESTDIR)${sysconfdir}/default/dumper

#
# Hooks
#

setcap:
if SETCAP
	test -e $(DESTDIR)$(bindir)/capdump && $(SETCAP) cap_net_raw+ep $(DESTDIR)$(bindir)/capdump || true
	test -e $(DESTDIR)$(bindir)/capshow && $(SETCAP) cap_net_raw+ep $(DESTDIR)$(bindir)/capshow || true
	test -e $(DESTDIR)$(bindir)/capdump && chmod o-rws $(DESTDIR)$(bindir)/capdump
	test -e $(DESTDIR)$(bindir)/capshow && chmod o-rws $(DESTDIR)$(bindir)/capshow
else
	@echo "ignoring setcap, use \`--enable-setcap' to enable."
endif

install-exec-hook: setcap
if BUILD_CAPSHOW
	cd $(DESTDIR)$(bindir) && test -h consumer-ls$(EXEEXT) || $(LN_S) capshow$(EXEEXT) consumer-ls$(EXEEXT)
endif

#
# Relase related targets
#

version=@VERSION@
debversion=`echo $(version) | sed 's/_//'`
debpkgname=libcap-utils_${debversion}_@ARCH@
releasedir=/var/marc/releases

deb: all check
	@test "x${prefix}" = "x/usr" || (echo "Error: --prefix must be /usr when creating debian release (currently ${prefix})"; exit 1)
	@test "x${sysconfdir}" = "x/etc" || (echo "Error: --sysconfdir must be /etc when creating debian release (currently ${sysconfdir})"; exit 1)
	echo b
	@test `id -u` = "0" || (echo "Error: must run as root to set proper permissions"; exit 1)
	echo c
	@test -e $(debpkgname) && rm -rf $(debpkgname) || true
	echo a
	mkdir -p $(debpkgname)/DEBIAN
	sed 's/_git/git/g'  < dist/deb-control > $(debpkgname)/DEBIAN/control
	cp ${top_srcdir}/dist/deb-postinst ${debpkgname}/DEBIAN/postinst
	echo "/etc/default/dumper" >  $(debpkgname)/DEBIAN/conffiles
	echo "/etc/init.d/dumper"  >> $(debpkgname)/DEBIAN/conffiles
	echo d
	$(MAKE) install DESTDIR=`pwd`/$(debpkgname)
	echo e
	strip `pwd`/$(debpkgname)/usr/bin/* `pwd`/$(debpkgname)/usr/lib/*.so
	echo f
	$(MAKE) install-dumper DESTDIR=`pwd`/$(debpkgname)
	echo g
	gzip -9 `pwd`/$(debpkgname)/usr/share/man/*/*
	find `pwd`/$(debpkgname) -name '*.la' -delete
	chmod 0755 `pwd`/$(debpkgname)/usr/bin/*
	(cd $(debpkgname); find . -type f ! -regex '.*.hg.*' ! -regex '.*?debian-binary.*' ! -regex '.*?DEBIAN.*' -printf '%P ' | xargs md5sum > DEBIAN/md5sums)
	dpkg-deb --build $(debpkgname)

# special target for dsvmarc releases
release_marc: dist distcheck deb
	cp $(distdir).tar.gz $(releasedir)
	cp $(debpkgname).deb $(releasedir)
	cat $(top_srcdir)//ChangeLog | awk -vRS= '{print; if ( NR == 2 ){ exit }}' > $(releasedir)/$(distdir).changelog.txt
