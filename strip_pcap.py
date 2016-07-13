#!/usr/bin/env python3

#strip_pcap.py - remove all packets from pcap that do not
#  meet triggers as defined in triggers.conf. This reduces
#  file size and allows for smoother parsing by the 
#  network visualization script.
import sys
try:
	from scapy.all import *
except ImportError:
	print(" === Scapy Not installed ===")
	print(" Please \'pip install scapy-python3\'")
	exit(1)

triggers = []

#Read, validate triggers.conf
def read_triggers_config(path="triggers.conf"):
	f = open(path)
	for line in f.readlines():
		#Skip commented out lines
		if line.startswith("//"):
			continue

		#Add trigger
		triggers.append(line.strip())

	#Clean up and exit
	f.close()
	return

#modified ver
def matchesTrigger(p, arr):
	try:
		src_ip = p[IP].src
		final_dst_ip = p[IP].dst
	except:
		return False

	proto = arr[0].split("=")[1].strip().upper()
	#Check protocol
	if proto == "*" or proto in p.summary().upper():
		#Check src
		if src_ip.startswith(arr[2].strip()) or arr[2].strip() == "*":
			#Check dst
			if final_dst_ip.startswith(arr[4].strip()) or "*" == arr[4].strip():
				return True
	return False

#See if any trigger matches
def meetsAnyTrigger(p):
	for t in triggers:
		arr = t.split(" ")
		if matchesTrigger(p, arr):
			return True
	return False


#Verify enough arguments
if len(sys.argv) < 4:
	print("Usage: ./strip_pcap.py /path/to/IN_FILE.pcap /path/to/OUT_FILE.pcap /path/to/triggers.conf")

in_path = sys.argv[1].strip()
out_path = sys.argv[2].strip()
trig_path = sys.argv[3].strip()

#read triggers
read_triggers_config(trig_path)

out = PcapWriter(out_path, append=True, sync=True)

processed = 0

with PcapReader(in_path) as pcap_reader:
	for pkt in pcap_reader:
		if meetsAnyTrigger(pkt):
			out.write(pkt)
		processed+=1
		if processed % 10000 == 0:
			print("Processed " + str(processed) + " packets")

print("Done!")

out.close()






