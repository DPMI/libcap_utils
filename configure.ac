m4_define([__VERSION_MAJOR__], [0])
m4_define([__VERSION_MINOR__], [7])
m4_define([__VERSION_MICRO__], [17])
m4_define([__VERSION_SUFFIX__], [-git])

AC_INIT([libcap_utils], m4_defn([__VERSION_MAJOR__]).m4_defn([__VERSION_MINOR__]).m4_defn([__VERSION_MICRO__])m4_defn([__VERSION_SUFFIX__]), [https://github.com/DPMI/libcap_utils])

VERSION_MAJOR=__VERSION_MAJOR__
VERSION_MINOR=__VERSION_MINOR__
VERSION_MICRO=__VERSION_MICRO__
VERSION_SUFFIX=__VERSION_SUFFIX__
VERSION_NUM=`printf "0x00%02d%02d%02d\n" ${VERSION_MAJOR} ${VERSION_MINOR} ${VERSION_MICRO}`

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign color-tests subdir-objects -Wall -Werror])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
  libcap_filter-0.7.pc
  libcap_marc-0.7.pc
  libcap_utils-0.7.pc
  caputils/version.h
  Makefile
  dist/deb-control
  dist/dumper_init
  tests/init.sh
])

AC_DEFINE_UNQUOTED([VERSION_MAJOR],  [${VERSION_MAJOR}], [Major version number of package])
AC_DEFINE_UNQUOTED([VERSION_MINOR],  [${VERSION_MINOR}], [Minor version number of package])
AC_DEFINE_UNQUOTED([VERSION_MICRO],  [${VERSION_MICRO}], [Micro version number of package])
AC_DEFINE_UNQUOTED([VERSION_SUFFIX], ["${VERSION_SUFFIX}"], [Suffix of package (e.g. git)])
AC_DEFINE_UNQUOTED([VERSION_FULL],   ["$VERSION"], [Verson number of package including suffixes (e.g. PF_RING)])
AC_SUBST([VERSION_MAJOR])
AC_SUBST([VERSION_MINOR])
AC_SUBST([VERSION_MICRO])
AC_SUBST([VERSION_SUFFIX])
AC_SUBST([VERSION_NUM])
AC_DEFINE_UNQUOTED([TOP_SRCDIR], ["${srcdir}"], [top source directory])

AX_DEFAULT_CFLAGS([-O2])
AC_PROG_SED
AM_PROG_CC_C_O
AC_PROG_CC_C99
AC_PROG_CXX
AC_PROG_LN_S
AC_ARG_PROGRAM
AC_USE_SYSTEM_EXTENSIONS
AC_DISABLE_STATIC([])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT
AC_SYS_LARGEFILE
AC_SEARCH_LIBS([clock_gettime], [rt])
AX_BE64
AX_IPV6
AX_IP_MTU

dnl Hide all symbols by default, if supported.
AX_VISIBILITY([
	AC_DEFINE([CAPUTILS_EXPORT], [1], [Export symbols from library])
	CFLAGS="$CFLAGS -fvisibility=hidden"
])

AC_ARG_ENABLE([debug], [AS_HELP_STRING([--enable-debug], [will print debugging information during runtime @<:@default=disabled@:>@])])
AS_IF([test "x$enable_debug" = "xyes"],
	[AC_DEFINE([DEBUG],  [1], [Define to enable extra debug prints])],
	[AC_DEFINE([NDEBUG], [1], [Define to disable extra debug prints])]
)

AC_ARG_WITH([pfring], [AS_HELP_STRING([--with-pfring], [Use PF_RING for ethernet capture @<:@default=auto@:>@])])
AX_PFRING([$with_pfring])
AM_CONDITIONAL([BUILD_PFRING], [test "x$ax_have_pfring" = "xyes"])
AS_IF([test "x$ax_have_pfring" = "xyes"], [AC_DEFINE_UNQUOTED([VERSION_FULL], ["$VERSION (PF_RING enabled)"])])

AC_ARG_ENABLE([capdump],   [AS_HELP_STRING([--enable-capdump],   [Build capdump utility (record a stream) @<:@default=enabled@:>@])])
AC_ARG_ENABLE([capinfo],   [AS_HELP_STRING([--enable-capinfo],   [Build capinfo utility (show info about a stream) @<:@default=enabled@:>@])])
AC_ARG_ENABLE([capfilter], [AS_HELP_STRING([--enable-capfilter], [Build capfilter utility (filter existing stream) @<:@default=enabled@:>@])])
AC_ARG_ENABLE([capmarker], [AS_HELP_STRING([--enable-capmarker], [Build capmarker utility @<:@default=enabled@:>@])])
AC_ARG_ENABLE([capmerge],  [AS_HELP_STRING([--enable-capmerge],  [Build capmerge utility @<:@default=enabled@:>@])])
AC_ARG_ENABLE([capshow],   [AS_HELP_STRING([--enable-capshow],   [Build capshow utility @<:@default=enabled@:>@])])
AC_ARG_ENABLE([utils],     [AS_HELP_STRING([--enable-utils],     [By default all utils are build, this flag disables all utils unless they are explicitly enabled. This also disables pcap support by default but can be explicitly enabled with --with-pcap])])
AC_ARG_WITH([pcap], [AS_HELP_STRING([--with-pcap@<:@=PREFIX@:>@], [Build utilities for conversion to and from pcap files. @<:@default=enabled@:>@])])

utils_unset="x"
AS_IF([test "x$enable_utils" = "xno"], [
	utils_unset=""

  dnl disable pcap by default if using --disable-utils as to reduce the
  dnl dependencies as much as possible.
  if test "x$with_pcap" = "x"; then
    with_pcap="no"
  fi
])

AM_CONDITIONAL([BUILD_CAPDUMP],   [test "x$enable_capdump"   = "xyes" -o "x$enable_capdump"   = "$utils_unset"])
AM_CONDITIONAL([BUILD_CAPINFO],   [test "x$enable_capinfo"   = "xyes" -o "x$enable_capinfo"   = "$utils_unset"])
AM_CONDITIONAL([BUILD_CAPFILTER], [test "x$enable_capfilter" = "xyes" -o "x$enable_capfilter" = "$utils_unset"])
AM_CONDITIONAL([BUILD_CAPMARKER], [test "x$enable_capmarker" = "xyes" -o "x$enable_capmarker" = "$utils_unset"])
AM_CONDITIONAL([BUILD_CAPMERGE],  [test "x$enable_capmerge"  = "xyes" -o "x$enable_capmerge"  = "$utils_unset"])
AM_CONDITIONAL([BUILD_CAPSHOW],   [test "x$enable_capshow"   = "xyes" -o "x$enable_capshow"   = "$utils_unset"])
AM_CONDITIONAL([BUILD_PCAP],      [test "x$with_pcap" != "xno"])
AM_CONDITIONAL([HAVE_VCS],        [test "x$VERSION_SUFFIX" = "x-git"])
AS_IF([test "x$VERSION_SUFFIX" = "x-git"], [AC_DEFINE([HAVE_VCS], [1], [Define to 1 if VCS is present])])
AX_PCAP($with_pcap)

AM_PATH_CPPUNIT(1.9.6,,[AC_MSG_NOTICE([cppunit not found, tests disabled])])
AM_CONDITIONAL([BUILD_TESTS], [test "x$no_cppunit" != "xyes"])

dnl Find out what arch is used for (debian) packaging.
dnl Includes a fulhack because debian is fucked^W using i386.
ARCH=`echo $host|cut -d '-' -f 1`
AS_IF([test "$ARCH" = "i686"], [ARCH="i386"])
AS_IF([test "$ARCH" = "x86_64"], [ARCH="amd64"])
AC_SUBST(ARCH)

dnl Check for setcap
have_setcap=no
AC_PATH_PROG(SETCAP, setcap,,"/sbin:$PATH")
AS_IF([test -n "$SETCAP"], [have_setcap=yes])
AC_ARG_ENABLE(setcap, AS_HELP_STRING([--enable-setcap], [install with cap_net_raw capability @<:@default=auto@:>@]),[
   AS_IF([test "x$enable_setcap" == "xyes" -a "x$have_setcap" == "xno"], [AC_MSG_ERROR([Could not find setcap, make sure it is installed or disable setcap.])])
   AS_IF([test "x$enable_setcap" != "xyes"], [have_setcap=no])
])
AM_CONDITIONAL(SETCAP, [test "x$have_setcap" == "xyes"])

AC_OUTPUT
