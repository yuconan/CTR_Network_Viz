# CTR Network Visualization Tool

A Network scenario visualization tool, under early development by Brent Younce for
the Cyber Test Range at the Laboratory for Analytic Sciences.

Usage: python3 script.py /path/to/network.conf /path/to/triggers.conf file.pcap<br />
If a pcap is not provided, script will sniff on default network interface

Dependencies: python3, scapy-python3, pygame-python3

To run the 'bigFlows' demo:<br />
	- Download 'bigFlows.pcap' from: http://tcpreplay.appneta.com/wiki/captures.html<br />
	- Run: python3 CTR_Network_Visualization.py examples/network_bigFlows.conf examples/triggers_bigFlows.conf /path/to/bigFlows.pcap

