DPMI capture utilities (libcap_utils)
=====================================
[![Build Status](https://travis-ci.org/DPMI/libcap_utils.svg?branch=master)](https://travis-ci.org/DPMI/libcap_utils)

Library and tools for working with network packet streams (traces) from a DPMI MA (measurement area) with one or more [measurement points](https://github.com/DPMI/mp).

It features tools for working with captured traces, including capture, splitting, merging, filtering, converting and displaying traces. Offline traces are similar to pcap (tcpdump, wireshark) but contains additional metadata and higher precision timestamps but most tools work just as well with live streams.

The library serves as a starting point for writing consumers which can perform live or offline analyzis (e.g. [bitrate](https://github.com/DPMI/consumer-bitrate), [oneway-delay](https://github.com/DPMI/consumer-onewaydelay), etc) of the captured streams (traces).

Documentation
-------------

Documentation is available at https://dpmi.github.io/libcap_utils. The public [API headers](caputils) also contains lots of documentations for library usage.

Installing
----------

See [Installing](https://dpmi.github.io/libcap_utils/#/0.7/install) for details.

    autoreconf -si
    mkdir build; cd build
    ../configure 
    make
    sudo make install

Usage
-----

Most tools have manpages and all of them support `--help`.

* `cap2pcap` - convert cap to pcap (libcap_utils to tcpdump).
* `capdump` - read a live stream (e.g. from a MP) and dump the trace to a file.
* `capfilter` - apply filters to a trace.
* `capinfo` - short information and generic statistics of a trace.
* `capmarker` - send a special marker packet through a live stream (easily identifiable by libcap_utils when doing analyzis).
* `capmerge` - merge two or more traces.
* `capshow` - display packets in a trace (tcpdump-style).
* `capwalk` - display packets in a trace (verbose deep decoding of all packets)
* `ifstat` - debugging utility
* `pcap2cap` - convert pcap to cap (tcpdump to libcap_utils).

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
