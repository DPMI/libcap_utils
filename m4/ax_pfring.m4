AC_DEFUN([AX_PFRING], [
  saved_CPPFLAGS="$CPPFLAGS"
  saved_LDFLAGS="$LDFLAGS"

  case $1 in
    yes | "")
      ax_pfring_path=
      ax_pfring_want="yes"
      ;;
    no)
      ax_pfring_want="no"
      ;;
    *)
      ax_pfring_path="$1"
      ax_pfring_want="yes"
      CPPFLAGS="$CPPFLAGS -I$ax_pfring_path/include"
      LDFLAGS="$LDFLAGS -L$ax_pfring_path/lib"
      ;;
  esac

  ax_have_pfring="no"
  AS_IF([test "x$ax_pfring_want" != "xno"], [
    LDFLAGS="$LDFLAGS -Wl,--undefined=pcap_compile_nopcap"
    AC_CHECK_HEADER([pfring.h])
    AC_CHECK_LIB([pfring], [pfring_open], [true])

    AS_IF([test "x$ac_cv_header_pfring_h" = "xyes" -a "x$ac_cv_lib_pfring_pfring_open" = "xyes"], [
      ax_have_pfring="yes"
      ax_pfring_cflags=
      ax_pfring_libs="-lpfring -lpcap"
      AS_IF([test "x$ax_pfring_path" != "x"], [
        ax_pfring_cflags="-I$ax_pfring_path/include"
        ax_pfring_libs="-L$ax_pfring_path/lib $ax_pfring_libs"
      ])

      AC_SUBST(PFRING_CFLAGS, [$ax_pfring_cflags])
      AC_SUBST(PFRING_LIBS, [$ax_pfring_libs])
      AC_DEFINE([HAVE_PFRING], 1, [Define to 1 if you have PF_RING])
    ], [
      AS_IF([test "x$1" != "x"], [AC_MSG_ERROR([Make sure the PF_RING userspace library is installed.])])
    ])
  ])

  CPPFLAGS="$saved_CPPFLAGS"
  LDFLAGS="$saved_LDFLAGS"
])
