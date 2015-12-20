AC_DEFUN([AX_BE64], [
  AC_LANG_PUSH([C])
  AC_MSG_CHECKING([for be64toh])
  saved_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS -Werror"
  AC_COMPILE_IFELSE([AC_LANG_SOURCE([
  #include <endian.h>
  #include <stdint.h>
  void foo(void){ uint64_t x = be64toh((uint64_t)0); }
  ])], [
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_BE64TOH], [], [Define to 1 if you have the be64toh function.])
    BE64TOH="yes"
  ], [
    AC_MSG_RESULT([no])
    BE64TOH="no"
  ])
  AM_CONDITIONAL([BUILD_BE64TOH], [test "x$BE64TOH" != "xyes"])
  CPPFLAGS="$saved_CPPFLAGS"
  AC_LANG_POP
])
