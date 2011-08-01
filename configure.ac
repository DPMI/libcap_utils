m4_define([__VERSION_MAJOR__], [0])
m4_define([__VERSION_MINOR__], [7])
m4_define([__VERSION_MICRO__], [2])

AC_INIT([libcap_utils],[__VERSION_MAJOR__.__VERSION_MINOR__.__VERSION_MICRO__], [dsv@bth.se])

VERSION_MAJOR=__VERSION_MAJOR__
VERSION_MINOR=__VERSION_MINOR__
VERSION_MICRO=__VERSION_MICRO__

AC_DEFINE_UNQUOTED([VERSION_MAJOR], [${VERSION_MAJOR}], [Major version number of package])
AC_DEFINE_UNQUOTED([VERSION_MINOR], [${VERSION_MINOR}], [Minor version number of package])
AC_DEFINE_UNQUOTED([VERSION_MICRO], [${VERSION_MICRO}], [Micro version number of package])
AC_SUBST([VERSION_MAJOR])
AC_SUBST([VERSION_MINOR])
AC_SUBST([VERSION_MICRO])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall foreign color-tests])
AM_SILENT_RULES([yes])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
	cap_utils.pc
	cap_filter.pc
	caputils/version.h
	Makefile
])

AC_PROG_CC_C_O
AC_PROG_CC_C99
AC_PROG_CXX
AC_GNU_SOURCE
AM_DISABLE_STATIC
LT_INIT

AC_ARG_ENABLE([debug], [AS_HELP_STRING([--enable-debug], [will print debugging information during runtime @<:@default=disabled@:>@])])
AS_IF([test "x$enable_debug" == "xyes"],
	[AC_DEFINE([DEBUG],  [1], [Define to enable extra debug prints])],
	[AC_DEFINE([NDEBUG], [1], [Define to disable extra debug prints])]
)

AC_ARG_ENABLE([capdump], [AS_HELP_STRING([--enable-capdump], [Build capdump utility (record a stream) @<:@default=enabled@:>@])])
AC_ARG_ENABLE([capinfo], [AS_HELP_STRING([--enable-capinfo], [Build capinfo utility (show info about a stream) @<:@default=enabled@:>@])])
AC_ARG_ENABLE([capfilter], [AS_HELP_STRING([--enable-capfilter], [Build capfilter utility (filter existing stream) @<:@default=enabled@:>@])])
AC_ARG_ENABLE([utils], [AS_HELP_STRING([--enable-utils], [By default all utils are build, this flag disables all utils unless they are explicitly enabled.])])

utils_unset="x"
AS_IF([test "x$enable_utils" == "xno"], [
	utils_unset=""
])

AM_CONDITIONAL([BUILD_CAPDUMP],   [test "x$enable_capdump"   == "xyes" -o "x$enable_capdump"   == $utils_unset])
AM_CONDITIONAL([BUILD_CAPINFO],   [test "x$enable_capinfo"   == "xyes" -o "x$enable_capinfo"   == $utils_unset])
AM_CONDITIONAL([BUILD_CAPFILTER], [test "x$enable_capfilter" == "xyes" -o "x$enable_capfilter" == $utils_unset])

AM_PATH_CPPUNIT(1.9.6)

AC_OUTPUT
