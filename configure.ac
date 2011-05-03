m4_define([__VERSION_MAJOR__], [0])
m4_define([__VERSION_MINOR__], [7])
m4_define([__VERSION_MICRO__], [0])

AC_INIT([libcap_utils],[__VERSION_MAJOR__.__VERSION_MINOR__.__VERSION_MICRO__], [dsv@bth.se])

VERSION_MAJOR=__VERSION_MAJOR__
VERSION_MINOR=__VERSION_MINOR__
VERSION_MICRO=__VERSION_MICRO__

AC_DEFINE_UNQUOTED([VERSION_MAJOR], [${VERSION_MAJOR}])
AC_DEFINE_UNQUOTED([VERSION_MINOR], [${VERSION_MINOR}])
AC_DEFINE_UNQUOTED([VERSION_MICRO], [${VERSION_MICRO}])
AC_SUBST([VERSION_MAJOR])
AC_SUBST([VERSION_MINOR])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall 1.11 silent-rules foreign])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_FILES([cap_utils.pc caputils/version.h Makefile])

AC_PROG_CC_C_O
AC_PROG_CC_C99
AC_GNU_SOURCE
AM_DISABLE_STATIC
LT_INIT

AC_ARG_ENABLE([debug],
	[AS_HELP_STRING([--enable-debug], [will print debugging information during runtime @<:@default=disabled@:>@])]
)

AS_IF([test "x$enable_debug" == "xyes"],
	[AC_DEFINE([DEBUG])],
	[AC_DEFINE([NDEBUG])]
)

AC_OUTPUT
