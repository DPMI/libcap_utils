libcap_utils
============

The libary is used by consumers to interface with the measurement stream and the [measurement points](https://github.com/DPMI/mp) use it to construct the measurement frames.

It features tools for working with captured traces, including capture, splitting, merging, filtering, converting and displaying traces.

Installing
----------

See INSTALL for details

    autoreconf -si
    mkdir build; cd build
    ../configure 
    make
    sudo make install

Usage
-----

Most tools have manpages and all of them support `--help`.

* `cap2pcap.c` - convert cap to pcap (libcap_utils to tcpdump).
* `capdump.c` - read a live stream (e.g. from a MP) and dump the trace to a file.
* `capfilter.c` - apply filters to a trace.
* `capinfo.c` - short information and generic statistics of a trace.
* `capmarker.c` - send a special marker packet through a live stream (easily identifiable by libcap_utils when doing analyzis).
* `capmerge.c` - merge two or more traces.
* `capshow.c` - display packets in a trace (tcpdump-style).
* `capwalk.c` - display packets in a trace (verbose deep decoding of all packets)
* `ifstat.c` - debugging utility
* `pcap2cap.c` - convert pcap to cap (tcpdump to libcap_utils).

Patches
-------

The preferred way to submit patches is to [fork the project](https://help.github.com/articles/working-with-forks/) and submit a [pull request](https://help.github.com/articles/using-pull-requests/). You can also email patches generated using `git format-patch` or a regular `diff -u`.

--
Version history
---------------

* Version 0.7 is reassemblied from the numerous different versions and with lots of code fixes. Major rewrite.
* Version 0.5 and 0.6 are almost the same, version 0.6 has fixed some bugs and added support for both full and variable size frames.
* Version >0.5, supports network streams (Ethernet, UDP and TCP) and files.
* Version 0.3, supports only files.
