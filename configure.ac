AC_INIT([libcap_utils],[0.5.1], [dsv@bth.se])
AC_DEFINE([VERSION_MAJOR], 0)
AC_DEFINE([VERSION_MINOR], 5)
AC_DEFINE([VERSION_MICRO], 1)

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall 1.11 silent-rules foreign])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_FILES([Makefile])

AC_PROG_CC_C_O
AM_DISABLE_STATIC
LT_INIT

AC_ARG_ENABLE([debug],
	[AS_HELP_STRING([--enable-debug], [will print debugging information during runtime @<:@default=disabled@:>@])],
	[AC_DEFINE([DEBUG])],
	[AC_DEFINE([NDEBUG])]
)

AC_OUTPUT
