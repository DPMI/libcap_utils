libcap_utils API examples
=========================

All examples can be built using `gcc -Wall SRC $(pkg-config libcap_utils-0.7 --libs) -o DST` (assuming libcap_utils is installed).

Overall it is a good idea to look through headers in the `caputils` folder and read the included manpages.

1. [Reading packets](01-reading_packets.c) - A rudimentary consumer which reads packets for a trace and prints packet sizes.
1. [Filtering packets](02-filtering_packets.c) - Creating packet filter pragmatically.
