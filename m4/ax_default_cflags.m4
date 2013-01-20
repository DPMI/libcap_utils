AC_DEFUN([AX_DEFAULT_CFLAGS], [
  AC_MSG_CHECKING([if CFLAGS is set])
  AS_IF([test -z "$CFLAGS"], [
    AC_MSG_RESULT([no, defaulting to "$1"])
    CFLAGS="$1"
    CXXFLAGS="$1"
  ], [
    AC_MSG_RESULT([yes ("$CFLAGS")])
  ])
])
