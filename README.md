# CTR Network Visualization Tool

A Network scenario visualization tool, under early development by Brent Younce for
the Cyber Test Range at the Laboratory for Analytic Sciences.

Usage: python3 CTR_Network_Visualization.py -t /path/to/triggers.conf -n /path/to/network.conf (options)<br />
	Options:<br />
	--ignore-whitenoise: hide all traffic that does not match a trigger<br />
	-p /path/to/file.pcap (or --pcap): read traffic from pcap (multiple supported!)<br />
	-a INTEGER (e.g. -a 7000): set time acceleration for pcap reading</br />


Dependencies: python3, scapy-python3, pygame-python3

To run the 'bigFlows' demo:<br />
	- Download 'bigFlows.pcap' from: http://tcpreplay.appneta.com/wiki/captures.html<br />
	- Run: python3 CTR_Network_Visualization.py -n examples/network_bigFlows.conf -t examples/triggers_bigFlows.conf -p /path/to/bigFlows.pcap

To run the routing demo on live network:<br />
	- Configure IPs (and, optionally, rules) in examples/network_Routing.conf to your LAN IPs<br />
	- Run: python3 CTR_Network_Visualization.py -n examples/network_Routing.conf -t examples/triggers_Routing.conf<br />

![Alt screenshot](img/screenshot_0.1.6.png?raw=true "bigFlows Demo")
	<br />
![Alt screenshot](img/screenshot2.png?raw=true "Routing Demo")
