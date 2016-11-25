# Tools: capshow

Use "--help" for detailed usage, and read the code for new features. 

## capshow-0.7.17-git[7e641fd/master]
(C) 2004 Patrik Arlos <patrik.arlos@bth.se>
(C) 2012 David Sveningsson <david.sveningsson@bth.se>
Usage: capshow [OPTIONS] STREAM
  -i, --iface          For ethernet-based streams, this is the interface to listen
                       on. For other streams it is ignored.
  -p, --packets=N      Stop after N read packets.
  -c, --count=N        Stop after N matched packets.
                       If both -p and -c is used, what ever happens first will stop.
  -t, --timeout=N      Wait for N ms while buffer fills [default: 1000ms].
      --version        Show program version and exit.
  -h, --help           This text.

## Formatting options:
  -1                   Show only DPMI information.
  -2                     .. include link layer.
  -3                     .. include transport layer.
  -4                     .. include application layer. [default]
  -H, --headers        Show layer headers.
  -x, --hexdump        Write full packet content as hexdump.
  -d, --calender       Show timestamps in human-readable format (UTC).
  -D, --localtime      Show timestamps in human-readable format (local time).
  -a, --absolute       Show absolute timestamps.
  -r, --relative       Show timestamps relative to first packet. [default]

## libcap_filter-0.7.17-git options
      --starttime=DATETIME      Discard all packages before starttime described by
                                the unix timestamp. See capfilter(1) for
                                additional accepted formats.
      --endtime=DATETIME        Discard all packets after endtime.
      --begin                   Alias for --starttime
      --end                     Alias for --endtime
      --mampid=STRING           Filter on MAMPid.
      --mpid=STRING             Alias for --mampid.
      --iface=STRING            Filter on networkinterface on MP.
      --if=STRING               Alias for --iface.
      --eth.vlan=TCI[/MASK]     Filter on VLAN TCI and mask.
      --eth.type=STRING[/MASK]  Filter on carrier protocol (IP, ARP, RARP).
      --eth.src=ADDR[/MASK]     Filter on ethernet source.
      --eth.dst=ADDR[/MASK]     Filter on ethernet destination.
      --ip.proto=STRING         Filter on ip protocol (TCP, UDP, ICMP).
      --ip.src=ADDR[/MASK]      Filter on source ip address, dotted decimal.
      --ip.dst=ADDR[/MASK]      Filter on destination ip address, dotted decimal.
      --tp.sport=PORT[/MASK]    Filter on source portnumber.
      --tp.dport=PORT[/MASK]    Filter on destination portnumber.
      --tp.port=PORT[/MASK]     Filter or source or destination portnumber (if
                                either is a match the packet matches).
      --frame-max-dt=TIME       Starts to reject packets after the interarrival-
                                time is greater than TIME (WRT matched packets).
      --frame-num=RANGE[,..]    Reject all packets not in specified range (see
                                capfilter(1) for further description of syntax).
      --caplen=BYTES            Store BYTES of the captured packet. [default=ALL]
      --filter-mode=MODE        Set filter mode to AND or OR. [default=AND]
      --bpf=FILTER              In addition to regular DPMI filter also use the
                                supplied BPF. Matching takes place after DPMI
                                filter.

## Output 
[pktCnt]:<CI>:<mpid>:<arrivaltime>:LINK(<L2 lenght>):CAPLEN( <captured bytes>):<NetworkProtocol>:<TransportInfo>:<Additional info>

## Output: UDP example
[   1]:d01::0.000000000000:LINK(  94):CAPLEN(  98):ID(   1): IPv4: UDP: 10.53.36.3:1985 --> 224.0.0.102:1985 len=60 check=7692
[   2]:d01::0.291647136250:LINK(  94):CAPLEN(  98):ID(   2): IPv4: UDP: 10.53.36.2:1985 --> 224.0.0.102:1985 len=60 check=2316

## Output: TCP example
[10843]:d00::774.438017189500:LINK(  60):CAPLEN(  64):ID( 744): IPv4: TCP: [A] 10.53.36.6:56351 --> 195.54.108.78:443 ws=16425 seq=1856428498 ack=1383033854
[10844]:d01::774.463548302750:LINK(1514):CAPLEN(1518):ID( 744): IPv4: TCP: [A] 195.54.108.78:443 --> 10.53.36.6:56351 ws=986 seq=1383035314 ack=1856428498



