# CTR Network Visualization Tool

A Network scenario visualization tool, under early development by Brent Younce for
the Cyber Test Range at the Laboratory for Analytic Sciences.

Usage: python3 CTR_Network_Visualization.py /path/to/network.conf /path/to/triggers.conf file.pcap [options]<br />
  If a pcap is not provided, script will sniff on default network interface<br />
  Optional: --ignore-whitenoise (at end of arguments) will hide any packet which does not meet a trigger defined in triggers.conf

Dependencies: python3, scapy-python3, pygame-python3

To run the 'bigFlows' demo:<br />
	- Download 'bigFlows.pcap' from: http://tcpreplay.appneta.com/wiki/captures.html<br />
	- Run: python3 CTR_Network_Visualization.py examples/network_bigFlows.conf examples/triggers_bigFlows.conf /path/to/bigFlows.pcap

To run the routing demo on live network:<br />
	- Configure IPs (and, optionally, rules) in examples/network_Routing.conf to your LAN IPs<br />
	- Run: python3 CTR_Network_Visualization.py examples/network_Routing.conf examples/triggers_Routing.conf<br />

![Alt screenshot](img/screenshot_0.1.6.png?raw=true "bigFlows Demo")
	<br />
![Alt screenshot](img/screenshot2.png?raw=true "Routing Demo")
