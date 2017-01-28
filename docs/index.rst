DPMI libcap_utils
=================

Library and tools for working with network packet streams (traces) from a DPMI
MA (measurement area) with one or more measurement points.  It features tools
for working with captured traces, including capture, splitting, merging,
filtering, converting and displaying traces. Offline traces are similar to pcap
(tcpdump, wireshark) but contains additional metadata and higher precision
timestamps but most tools work just as well with live streams.

The library serves as a starting point for writing consumers which can perform
live or offline analyzis (e.g. bitrate, oneway-delay, etc) of the captured
streams (traces).

.. toctree::
   :maxdepth: 1
   :caption: Contents:

   overview
   install
   consumers
   api

.. toctree::
   :maxdepth: 1
   :caption: Tools:

   tools
   capshow


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
