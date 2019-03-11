NIDS:

I first checked if the packets are going through the Interface or through a pcap which would determine whether to read the file or to sniff in case of scapy. Then, I find the network.
If enabled, I compute ipv4 and tcp checksums. For every packet, flags and frag bits are checked to figure out if the packets should be reassembled for iPv4 fragment by using the default or current bahvior as described.
TCP reassembly is performed using pynids. After TCP reassembly, the destination port and the content are matched from the config file and the data is searched for the regex in the defragmented TCP and displayed.
