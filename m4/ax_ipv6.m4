AC_DEFUN([AX_IPV6], [
  AC_CHECK_HEADER([netinet/ip6.h], [
    AC_DEFINE([HAVE_NETINET_IP6_H], [1], [Define to 1 if you have the <netinet/ip6.h> header file])
    AC_DEFINE([HAVE_IPV6], [1], [Define to 1 if you have IPv6 support])

    AC_LANG_PUSH([C])
    AC_MSG_CHECKING([for ip6_ext in netinet/ip6.h])
    saved_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS -Werror"
    AC_COMPILE_IFELSE([AC_LANG_SOURCE([
    #include <netinet/ip6.h>
    int main(void){ return sizeof(struct ip6_ext); }
    ])], [
      AC_MSG_RESULT([yes])
      AC_DEFINE([HAVE_IP6_EXT], [1], [Define to 1 if struct ip6_ext is available])
    ], [
      AC_MSG_RESULT([no])
    ])
    CPPFLAGS="$saved_CPPFLAGS"
    AC_LANG_POP
  ])
])
