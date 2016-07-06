# CTR_Network_Viz

A Network scenario visualization tool, developed by Brent Younce for
the Cyber Test Range at the Laboratory for Analytic Sciences.

Usage: python3 script.py PATH_OF_network.conf PATH_OF_triggers.conf file.pcap
   If a pcap is not provided, script will sniff on default network interface

To run the 'bigFlows' demo:
	- Download 'bigFlows.pcap' from: http://tcpreplay.appneta.com/wiki/captures.html
	- Run: python3 CTR_Network_Visualization.py examples/network_bigFlows.conf examples/triggers_bigFlows.conf /path/to/bigFlows.pcap

