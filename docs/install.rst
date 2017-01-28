Install instructions
====================

.. code-block:: bash

   autoreconf -si
   mkdir build;
	 cd build
   ../configure 
   make
   sudo make install
 
If needed, update ldconfig search path (e.g `/etc/ld.so.conf.d`) to be aware of
the new library files.

Step by step instructions
-------------------------

This document describes how to install from source, for supported distributions
see the instructions at install.

Prerequisites
-------------

... code-block:: bash

   apt-get install build-essential autoconf libtool rrdtool librrd-dev libxml2-dev pkg-config libpcap-dev libssl-dev

(or equivalent if your not using a Debian/Ubuntu based distribution)

Optionally have PF_RING and/or DAG drivers installed.

Obtaining the sources
---------------------

Either fetch the source via :bash:`git clone
https://github.com/DPMI/libcap_utils.git` or acquire a tarball and extract it as
usual.


General instructions
--------------------

If you got the sourcecode via git you need to run `autoreconf -si` to bootstrap
the build system.

.. code-block: bash
	 
   mkdir build && cd build
   ../configure
   make
   sudo make install

Certain libraries (like `pcap`, `DAG` and `PF_RING`) have options like
`--with-pcap=PREFIX` which allows building from non-standard locations,
e.g. `./configure --with-pcap=/usr/local` will use pcap from `/usr/local` even
if the path isn't normally searched by gcc (it will append -I and -L).

Use `configure --help` to see all available options.

Prefixed installation
---------------------

For a temporary installation, personal copy, or if multiple versions of the
software is required the usage of a prefix in your home-directory is
suggested. Unless installing system-wide, consider a prefix.

The prefix is a path which is prefixed in front of all installed files (e.g. if
a tool is to be installed to `/bin/foobar` and the prefix `/home/fred/myPrefix`
is used, the tool will be installed to `/home/fred/myPrefix/bin/foobar`).

There is many good reasons why to use a prefix:

* Do not have to be root to install.
* Simply wipe the directory and the software is completely uninstalled, won't
  scatter files all over the system.
* Easy to manage multiple installations.

To add a prefix use `--prefix /path/to/prefix` when running configure and use
`PKG_CONFIG_PATH=/path/to/prefix/lib/pkgconfig` to tell `pkg-config` where to
look for the files. In addition you need `LD_LIBRARY_PATH=/path/to/prefix/lib`
and it is useful to put the path in `PATH` as well.

You can run the following lines in a shell, or put them in `.bashrc` or similar:

.. code-block:: bash
								
   export DMPI_PREFIX=/path/to/prefix
   export PKG_CONFIG_PATH=${DPMI_PREFIX}/lib/pkgconfig:${PKG_CONFIG_PATH}
   export LD_LIBRARY_PATH=${DPMI_PREFIX}/lib:${LD_LIBRARY_PATH}
   export PATH=${DPMI_PREFIX}/bin:${PATH}
   export MANPATH=${DPMI_PREFIX}/share/man:${MANPATH}

Debian/Ubuntu packages
----------------------

To build and install debian `.deb` you need to configure with some specific
paths and then run `make deb`.

.. code-block:: bash
								
   ./configure --prefix=/usr --sysconfdir=/etc
   make deb
   dpkg -i PACKAGE.deb

This is the recommended way to install the software if you do not intend to edit
the source-code.

Optional features
-----------------

PF_RING
~~~~~~~

1. Download and install `PF_RING` from ntop_. There is a Makefile to generate
   debian/ubuntu packages in packages/ubuntu.
2. `configure --with-pfring`

.. _ntop: http://www.ntop.org/products/packet-capture/pf_ring/

`PF_RING` replaces `SOCK_RAW` ethernet capture.

DAG
~~~

Use `--with-dag[=PATH]` or `--with-dag-legacy[=PATH]` for enable support for DAG
cards where the later is using old drivers for linux 2.4.


Capmarker
~~~~~~~~~

To only install capmarker (and library) use `../configure --disable-utils
--enable-capmarker`. Useful when you only want to send markers without
installing a full DPMI stack.

Troubleshooting
---------------

configure: error: Package requirements were not met
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

   Package requirements (...) where not met
   
   configure: error: Package requirements (libmarc-0.7 >= 0.7.0) were not met:
   No package 'libmarc-0.7' found
   
   Consider adjusting the PKG_CONFIG_PATH environment variable if you
   installed software in a non-standard prefix.

   Alternatively, you may set the environment variables libmarc_CFLAGS
   and libmarc_LIBS to avoid the need to call pkg-config.
   See the pkg-config man page for more details.

This happens because `pkg-config` could not locate the library. Make sure it is
installed and `PKG_CONFIG_PATH` points to the lib/pkgconfig path in the prefix.

The pkg-config script could not be found or is too old
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

   configure: error: The pkg-config script could not be found or is too old. Make sure it is in your PATH or set the PKG_CONFIG environment variable to the full path to pkg-config.

Read the actual error, then to install/upgrade pkg-config. (e.g. apt-get install
pkg-config)

Library not found during relinking
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

   libtool: install: warning: relinking `libcap_utils-07.la'
   libtool: install: (cd /home/dsv/libcap_utils-0.7.7; /bin/bash /home/dsv/libcap_utils-0.7.7/libtool  --silent --tag CC --mode=relink gcc -std=gnu99 -Wall -g -O2 -version-info 0:1:0 -o libcap_utils-07.la -rpath /usr/lib address.lo error.lo log.lo marker.lo utils.lo picotime.lo libcap_stream-07.la libcap_filter-07.la libcap_marc-07.la -inst-prefix-dir /home/dsv/libcap_utils-0.7.7/libcap-utils_0.7.7_amd64)
   /usr/bin/ld: cannot find -lcap_stream-07
   collect2: ld returned 1 exit status
   libtool: install: error: relink `libcap_utils-07.la' with the above command before installing it

Start swearing, install an older version and try again.
