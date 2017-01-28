# Tools

Most tools have manpages and all of them support `--help` for detailed usage.

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

## Use-cases

### Save a live MP stream to local file

    capdump -i eth0 -o trace.cap 01::10

### Show contents of a saved trace

    capshow trace.cap


### Show the content of two live streams
    
    capshow -i eth0 01::10 01::01
    
    
### Merge two traces to a single file

    capmerge -o merged.cap trace1.cap trace2.cap
