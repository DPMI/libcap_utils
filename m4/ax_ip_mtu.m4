AC_DEFUN([AX_IP_MTU], [
  AC_LANG_PUSH([C])
  AC_MSG_CHECKING([for IP_MTU in netinet/ip.h])
  saved_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS -Werror"
  AC_COMPILE_IFELSE([AC_LANG_SOURCE([
  #include <netinet/ip.h>
  int main(void){ return IP_MTU; }
  ])], [
    AC_MSG_RESULT([yes])
  ], [
    AC_MSG_RESULT([no])
    AC_MSG_CHECKING([for IP_MTU in linux/in.h])
    dnl This probably fails if crosscompiling
    ip_mtu=`$SED -nr 's/.*@<:@ \t@:>@IP_MTU@<:@ \t@:>@+(@<:@0-9@:>@+)$/\1/p' /usr/include/linux/in.h`
    AS_IF([test -n "$ip_mtu"], [
      AC_MSG_RESULT([yes])
      AC_DEFINE_UNQUOTED([IP_MTU], [$ip_mtu], [Fallback value when netinet/ip.h does not provide this enumeration])
    ], [
       AC_MSG_RESULT([no])
      AC_MSG_ERROR([No definition of IP_MTU could be located])
    ])
  ])
  CPPFLAGS="$saved_CPPFLAGS"
  AC_LANG_POP
])
