AC_DEFUN([AX_PCAP], [
  saved_CPPFLAGS="$CPPFLAGS"
  saved_LDFLAGS="$LDFLAGS"

  case $1 in
    yes | "")
      ax_pcap_path=
      ax_pcap_want="yes"
      ;;
    no)
      ax_pcap_want="no"
      ;;
    *)
      ax_pcap_path="$1"
      ax_pcap_want="yes"
      CPPFLAGS="$CPPFLAGS -I$ax_pcap_path/include"
      LDFLAGS="$LDFLAGS -I$ax_pcap_path/lib"
      ;;
  esac

  AS_IF([test "x${ax_pcap_want}" == "xyes"], [
    AC_CHECK_HEADER([pcap/pcap.h],[
      AC_CHECK_LIB([pcap], [pcap_close], [
        ax_pcap_cflags=
        ax_pcap_libs=-lpcap

        AS_IF([test "x$ax_pcap_path" != "x"], [
          ax_pcap_cflags="-I$ax_pcap_path/include"
          ax_pcap_libs="-L$ax_pcap_path/lib $ax_pcap_libs"
        ])

        AC_SUBST(PCAP_CFLAGS, [$ax_pcap_cflags])
        AC_SUBST(PCAP_LIBS, [$ax_pcap_libs])
        AC_DEFINE([HAVE_PCAP], 1, [Define to 1 if you have libpcap])
      ], [
        AC_MSG_ERROR([Make sure libpcap is installed.])
      ])
    ], [
      AC_MSG_ERROR([Make sure libpcap is installed.])
    ])
  ]) dnl if ${ax_pcap_want}

  CPPFLAGS="$saved_CPPFLAGS"
  LDFLAGS="$saved_LDFLAGS"
])
