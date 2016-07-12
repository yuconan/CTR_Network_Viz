#!/usr/bin/env python3

#Network (attack) visualization tool Proof-Of-Concept / Early Beta
#Author: Brent Younce (brent@younce.me, bjyounce@ncsu.edu)
#For the Cyber Test Range at LAS

#Import standard lib dependencies
import math, uuid, random, socket, os.path
import _thread as thread
from time import sleep
#Import external dependencies
try:
	from scapy.all import *
except ImportError:
	print(" === Scapy Not installed ===")
	print(" Please \'pip install scapy-python3\'")
	exit(1)
try:
	import pygame
except ImportError:
	print(" === PyGame not installed ===")
	print(" Please install pygame for python3")
	exit(1)


pygame.init()

viz_accel = 1.0 #Time Acceleration in scapy_parse_pcap

#initialize screen
screen_width = 800
screen_height = 450
screen = None
pygame.display.set_caption("CTR Network Visualization Tool BETA (v.0.2.0)")
#placeholder for app exit var
done = False
ignore_whitenoise = False
has_Internet_node = False
#IP address font (bundled TTF)
font = pygame.font.Font("Roboto.ttf", 18)


#list of nodes (computers on network to display)
nodes = []
#list of packets currently active
packets = []
#trigger list (read from conf file)
triggers = []
#Routing rule list
routing_rules = []
#Connections
lines = []

#packet colors
color_udp = "#00ee00"
color_tcp = "#00ee00"
color_trigger = "#ff0000"

#Functions

#========================== Scapy Functions ==========================

#Callback function - this is called on thread 2 after scapy
# reads a packet from the wire automatically, or manually
# after each packet from a pcap
def scapy_callback(p):
	src = "Internet"
	dst = "Internet"
	size = 5

	#Verify only IP packets are processed
	try:
		p[IP]
	except:
		return

	#Map Packet source to existing node
	#If no existing node, default to Internet
	for node in nodes:
		if p[IP].src.startswith(node.ip):
			src = node.ip
		if p[IP].dst.startswith(node.ip):
			dst = node.ip
	#if src == dst, usually Internet == Internet, 
	# usually caused by communication between nodes
	# not included in network.conf. 
	if src == dst: 
		return #ignore packet, do not draw
	#If Internet node is not present
	if src == "Internet" or dst == "Internet":
		if not has_Internet_node:
			return
			
	#Color based on TCP or UDP
	if "TCP" in p:
		color = color_tcp
	else:
		color = color_udp

	obj = Packet( p, src, dst, color, size)
	if not (ignore_whitenoise and obj.isWhitenoise()):
		packets.append ( obj )

#Sniff network, call callback function on each packet
def scapy_sniff():
	sniff(filter="ip",prn=scapy_callback) 

#Automatic sniffing from pcap (realtime)
def scapy_sniff_pcap(path):
	sniff(filter="ip", prn=scapy_callback, offline=path)

#Parse pcap file manually. This should support time acceleration,
# and allow for more customization than scapy_sniff_pcap
def scapy_parse_pcap(path, accel=viz_accel):
	with PcapReader(path) as pcap_reader:
		last_time = None
		for pkt in pcap_reader:
			if last_time is None:
				delay = 0.0
			else:
				#Delay between current packet and next
				delay = (pkt.time - last_time)/accel
			#Update last time
			last_time = pkt.time
			#Wait time difference between packets
			sleep(delay)
			#Display packet
			#ISSUE: this takes time, causing delay to be off and slow
			# potential solution: third thread for display queue (TODO)
			scapy_callback(pkt) 
		print("Done")
	

#========================== Data Manipulation Functions ==========================

#get node from node list by IP address
def getNodeByIP(ip_addr):
	for node in nodes:
		if node.ip.startswith(ip_addr):
			return node
	#raise exception if non existant
	raise Exception("Node does not exist")
	return

#Validate IP by attempting to parse it
def isValidIP(ip):
	try:
		socket.inet_aton(ip)
		return True
	except socket.error:
		return False

#Validate int
def isInt(i):
	try:
		int(i)
		return True
	except:
		return False

#Validate file
def isFile(path):
	return os.path.isfile(path)


#Read & parse network.conf
def read_network_config(path="network.conf"):
	global has_Internet_node

	f = open(path)
	for line in f.readlines():
		#Skip commented or blank lines
		if line.startswith("//") or line.isspace():
			continue

		arr = line.split(" ")
		#Determine device type (the string 'type' itself is reserved)
		kind = str(arr[0]).strip().upper()
		if kind == "NODE":
			#Parse Node
			try:
				#basic parsing
				ip = str(arr[1])
				name = str(arr[2])
				x = int(arr[3])
				y = int(arr[4])
				path = str(arr[5]).strip()
			except:
				print("Skipping invalid network config entry: \'" + str(line).strip() + "\'")
				continue

			#2nd round input validation
			if not ( (0 <= x <= screen_width) and (0 <= y <= screen_height)):
				print("Invalid coordinate on network cfg line: \'" + str(line).strip() + "\', skipping")
				continue

			#Validate image path (if provided)
			if not isFile(path):
				print("Invalid file path on network cfg line: \'" + str(line).strip() + "\', skipping")
				continue

			if ip == "Internet":
				has_Internet_node = True

			nodes.append( Node(ip, name, x, y, path) )


		#Read Routing Rules
		elif kind == "RULE":
			routing_rules.append(line.strip())
			
			#TODO: Validate Routing Rules

		elif kind == "LINE":
			try:
				ip1 = str(arr[1].strip())
				ip2 = str(arr[2].strip())
				#validate IPs
				getNodeByIP(ip1)
				getNodeByIP(ip2)
				#okay, they exist, lets add
				lines.append( [ip1, ip2] )
			except IndexError: #thrown if IPs not given in line
				print("Missing IPs in Line entry on network cfg line: \'" + str(line).strip() + "\', skipping")
				continue
			except: #generic exception thrown by getNodeByIP
				print("Invalid IPs in Line entry on network cfg line: \'" + str(line).strip() + "\', skipping")
				continue


		else:
			print("Invalid entry on network cfg line: \'" + str(line).strip() + "\', skipping")
			continue

		
	f.close()
	return

#Read, validate triggers.conf
def read_triggers_config(path="triggers.conf"):
	f = open(path)
	for line in f.readlines():
		#Skip commented out lines
		if line.startswith("//") or line.isspace():
			continue

		#Add trigger
		triggers.append(line.strip())

	#Clean up and exit
	f.close()
	return


# ========================== pyGame (Graphics) Functions ==========================

#calculate movement vector from pt1 to pt2
#  Math code from stack overflow
def calc_vector(t0,t1,psx,psy,speed):
	global mx
	global my

	speed = speed

	distance = [t0 - psx, t1 - psy]
	norm = math.sqrt(distance[0] ** 2 + distance[1] ** 2)
	direction = [distance[0] / norm, distance[1 ] / norm]

	bullet_vector = [direction[0] * speed, direction[1] * speed]
	return bullet_vector

#Validate color by attempting to parse it
# this method allows for users to enter
# RGB(a) values, hex values, etc.

#No longer used. Deprecated?
def isValidPygameColor(c):
	try:
		pygame.Color(c)
		return True
	except:
		return False

#========================== Object Classes ==========================

#One computer in the network
class Node:
	#instance vars
	ip = "127.0.0.1"
	x = 30
	y = 30
	img = None
	name = None

	# "constructor"
	def __init__(self, new_ip, new_name, x_pos, y_pos, img_path=None):
		self.ip = new_ip
		self.x = x_pos
		self.y = y_pos
		self.img = pygame.image.load(img_path)
		if new_name == None or len(new_name.strip()) == 0:
			self.name = ip
		else:
			self.name = new_name.strip()

	#Display self
	def update(self):
		#Draw Image
		screen.blit(self.img, (self.x,self.y))
		#Draw Rectangle
	##	else:
	##		pygame.draw.rect(screen, self.color, pygame.Rect(self.x,self.y,60,60))
		#display text
		text = font.render(self.name, True, (0,0,0))
		text_width, text_height = font.size(self.name)

		screen.blit(text, (self.x+32-(text_width/2), self.y+70))

#One packet to be displayed
class Packet:
	p = None
	unique_id = None #UUID
	orig_size = 5
	size = 5
	x = 0 #current position
	y = 0
	next_dst_ip = None
	final_dst_ip = None
	src_ip = None
	vector = [] #direction vector

	color = pygame.Color("#ff0000")

	#Calc vector to next hop, based on routing rules
	def calcNextHop(self):
		has_matched = False
		#Parse routing rules
		for rule in routing_rules:
			parts = rule.split(" ")
			#See if we match 'from' in rule (we've already arrived at next_dst_ip)
			if parts[2].strip() == "*" or self.next_dst_ip.startswith(parts[2].strip()):
				#Match from, do we match to?
				if parts[4].strip() == "*" or self.final_dst_ip.startswith(parts[4].strip()):
					#Match
					self.next_dst_ip = str(parts[6].strip())
					has_matched = True
					break
		#No routing rules match
		if not has_matched:
			self.next_dst_ip = self.final_dst_ip

		#Find coordinates, calculate vector to next hop
		self.next_hop_x = getNodeByIP(self.next_dst_ip).x+30
		self.next_hop_y = getNodeByIP(self.next_dst_ip).y+30
		self.next_hop_x+=random.uniform(-5,5) #aesthetics
		self.next_hop_y+=random.uniform(-5,5)
		self.vector = calc_vector(self.next_hop_x,self.next_hop_y, self.x, self.y, 10)
		self.size = self.orig_size
		return

	#After splitting a trigger line and determining the trigger type,
	#  this function tests it the trigger matches. It exists to remove
	#  redundent code which would be in place in every checkXXXTrigger
	#  function.
	def matchesTrigger(self, arr):
		proto = arr[0].split("=")[1].strip().upper()
		#Check protocol
		if proto == "*" or proto in self.p.summary().upper():
			#Check src
			if self.src_ip.startswith(arr[2].strip()) or arr[2].strip() == "*":
				#Check dst
				if self.final_dst_ip.startswith(arr[4].strip()) or "*" == arr[4].strip():
					return True
		return False

	#See if any trigger matches
	def isWhitenoise(self):
		for t in triggers:
			arr = t.split(" ")
			if self.matchesTrigger(arr):
				return False
		return True


	#At beginning, check for applicable 'highlight' triggers
	def checkHighlightAndDisplayTriggers(self):
		for t in triggers:
			arr = t.split(" ")
			kind = arr[5].strip().upper()
			#make sure we match trigger first
			if not self.matchesTrigger(arr):
				continue

			if kind == "HIGHLIGHT":
				#Apply highlight
				self.size = 10
				self.orig_size = 10
				self.color = pygame.Color(color_trigger)
			elif kind == "DISPLAY":
				self.size = 5
				self.orig_size = 5
				self.color = pygame.Color(color_udp)
			elif kind == "CHANGE_SRC_ICON":
				#may be inefficient in bulk
				getNodeByIP(self.src_ip).img = pygame.image.load(arr[6].strip())
			elif kind == "COLOR":
				self.color = pygame.Color(str(arr[6].strip()))
			elif kind == "HIDE":
				self.deleteSelf()


	#"Impact" triggers
	def checkImpactTriggers(self):
		for t in triggers:
			arr = t.split(" ")
			if not self.matchesTrigger(arr):
				continue

			if arr[5].strip().upper() == "CHANGE_DST_ICON":
				#may be inefficient in bulk
				getNodeByIP(self.final_dst_ip).img = pygame.image.load(arr[6].strip())
				continue



	#find self in list via UUID, delete
	def deleteSelf(self):
		global packets
		for p in packets: #find self in list
			if p.unique_id == self.unique_id: #identify by UUID
				packets.remove(p) #delete
				return
		print("Couldnt find it")

	#Delete self if necessary, move, & draw
	def update(self):
		#Shrink as approaching destination
		if self.next_dst_ip.startswith(self.final_dst_ip) and abs(self.x - self.next_hop_x) < 20 and abs(self.y - self.next_hop_y) < 20:
			self.size = int(self.size/2)

		#If packet is very close to destination, delete
		if(abs(self.x - self.next_hop_x) < 10 and abs(self.y - self.next_hop_y) < 10):
			#If we've reached final hop
			if(self.final_dst_ip.startswith(self.next_dst_ip)):
				self.checkImpactTriggers()
				self.deleteSelf()
			else:
				self.calcNextHop()
		else:
			#draw
			self.x+=self.vector[0]
			self.y+=self.vector[1]
			pygame.draw.circle(screen, (self.color), (int(self.x),int(self.y)), self.size)

	def __init__(self, packet, src_ip, target_ip, c="#ff0000", s=5):
		#generate a UUID for packet identification for deletion
		self.unique_id = uuid.uuid4() 

		#set starting coords to center of source square
		self.x = getNodeByIP(src_ip).x+30
		self.y = getNodeByIP(src_ip).y+30
		self.p = packet
		self.src_ip = src_ip
		#set color
		self.color = pygame.Color(c)
		#set size
		self.size = s
		self.orig_size = s

		#Add small amount of randomness to starting & target coords
		#  for aesthetics. Makes packets not all happen on a single line
		self.x+=random.uniform(-5,5)
		self.y+=random.uniform(-5,5)

		self.final_dst_ip = target_ip

		#Default next_dst_ip to src_ip for calcNextHop()
		self.next_dst_ip = src_ip

		#Calculate path to next hop
		self.calcNextHop()
		#"Highlight" and "Display" triggers can be applied now
		self.checkHighlightAndDisplayTriggers()


#========================== Main ==========================

def showHelp():
	print("Usage: python3 CTR_Network_Visualization.py -t /path/to/triggers.conf -n /path/to/network.conf [options]")
	print("  Options:")
	print("    --ignore-whitenoise: hide all traffic that does not match a trigger")
	print("    -p /path/to/file.pcap (or --pcap): read traffic from pcap (multiple supported!)")
	print("    -a INTEGER (e.g. -a 7000): set time acceleration for pcap reading")


#Read args - code adapted from Brent Younce's Excalibur-CLI tool
args = sys.argv[1:] #Get all arguments in an array	

nconf_path = None #network.conf location
tconf_path = None #triggers.conf location
pcap_paths = [] #paths of pcaps to read from

#find the length of the array for loops later on
l = len(args)
if l == 0:
	showHelp()
	exit(1)

#Collect, go through arguments
for i in range(0,l):
	currarg = str(args[i])
	currarg_lower = currarg.lower() #we still need original
	nextarg = None #helpful for -X VAL
	if(i < l-1):
		nextarg = args[i+1].strip()
	#Begin parsing arguments
	if currarg_lower == "-h" or currarg_lower == "help":
		showHelp()
	#Parse network.conf
	elif currarg_lower == "-n":
		if nextarg == None:
			print(">>> -n requires the path of your network.conf <<<")
			print(">>> Example: -n /root/network.conf            <<<")
		else:
			nconf_path = nextarg
	#Parse triggers.conf
	elif currarg_lower == "-t":
		if nextarg == None:
			print(">>> -t requires the path of your triggers.conf<<<")
			print(">>> Example: -t /root/triggers.conf           <<<")
		else:
			tconf_path = nextarg
	#Parse pcap
	elif currarg_lower == "-p" or currarg_lower == "--pcap":
		if nextarg == None:
			print(">>> -p or --pcap requires a pcap path         <<<")
			print(">>> Example: --pcap /root/file.pcap           <<<")
		else:
			pcap_paths.append(nextarg)
	#Parse --ignore-whitenoise
	elif currarg_lower == "-i" or currarg_lower == "--ignore-whitenoise":
		ignore_whitenoise = True
	#Parse pcap time acceleration
	elif currarg_lower == "-a" or currarg_lower == "--accel" or currarg_lower == "--acceleration":
		if nextarg == None or not isInt(nextarg):
			print(">>> -a or --accel requires an integer argument <<<")
			print(">>> Example: --accel 1000                      <<<")
		else:
			viz_accel = int(nextarg)
			print("Time acceleration set to " + str(viz_accel) + "X")


#Ensure essential arguments are present
if nconf_path == None or tconf_path == None:
	showHelp()
	exit(1)

#Read, parse network.conf
read_network_config(nconf_path)

#Read, parse triggers.conf
read_triggers_config(tconf_path)


#launch sniffers
if len(pcap_paths) == 0:
	thread.start_new_thread(scapy_sniff, ())
else:
	for path in pcap_paths:
		thread.start_new_thread(scapy_parse_pcap, (path,viz_accel,))

#TODO: acceleration with scapy_parse_pcap function

#Turn on screen
screen = pygame.display.set_mode((screen_width, screen_height))
#main 'game' loop
while not done:
	#analyze each pygame input event
	for event in pygame.event.get():
		#exit
		if event.type == pygame.QUIT:
			done = True
			break

	#Note: Double commented code here is 'dead code', intended as a reference
	# for future programming.

		##elif event.type == pygame.KEYDOWN and event.key == pygame.K_SPACE:
		##	is_online = not is_online

	#analyze key input
	##pressed = pygame.key.get_pressed()
	##if pressed[pygame.K_UP]: y -= 3
	##if pressed[pygame.K_DOWN]: y += 3
	##if pressed[pygame.K_LEFT]: x -= 3
	##if pressed[pygame.K_RIGHT]: x += 3

	#empty screen
	screen.fill((255,255,255))
	#screen.fill(pygame.Color("#b3b3b3"))

	for line in lines:
		#TODO: fix color issue
		pygame.draw.aaline(screen, (50,50,50), [getNodeByIP(line[0]).x+32, getNodeByIP(line[0]).y+32], [getNodeByIP(line[1]).x+32, getNodeByIP(line[1]).y+32], 2)

	#display all nodes
	for node in nodes:
		node.update()

	#display all packets
	for packet in packets:
		packet.update()

	#update screen (double buffering)
	pygame.display.flip()


#TODO:
	# - Test with more datasets, develop new examples
	# - Add packet display scaling option
	# -> Add more trigger options <-

#Minor TODO:
	# - Add more checking of conf files

#========================== Changelog ==========================
#0.2.0 (BETA 1) UNDER DEVELOPMENT
	# This update focuses on fixing bugs, making code cleaner,
	#   and adding more user input error checking. At this point,
	#   the script contains many of the features it was originally
	#   intended to have, although not all.
	#
	# - Added input error checking for network.cfg LINE entries
	# - Overhauled argument parsing
	#   - Added support for -a/--accel in the process
	#	- Added (experimental) support for multiple pcaps
	# - Added 'hide' trigger


#0.1.8 (Triggers.conf update pt 2)
	# - Added 'display' trigger (for --ignore-whitenoise or strip_pcap)
	# - Added 'change_dst_icon' and 'change_src_icon' triggers
	# - Added 'color' trigger
	# - Fixed trigger filter matching bug

#0.1.7 (Time Acceleration)
	# - Changed primary parse function to scapy_parse_pcap
	# - Added strip_pcap script
	# - Added support for startswith (whole subnet) nodes

#0.1.6 (Visuals & More)
	# - Tweaked protocol trigger code, many more protocols should now
	#   be supported
	# - New font (Roboto - android's new Material Design font)
	# - New icons: both demos now have much more modern design

#0.1.5 (Triggers.conf update pt 1)
	# - Increased information present and filters available
	#   in triggers.conf
	# - Added drawable lines to network conf file
	# - Fixed --ignore-whitenoise

#0.1.4 (Visual Options)
	# - Names now seperate entry from IP addresses
	# - second icon set added
	# - minor cleanup, bug fixes

#0.1.3 (New Options)
	# - Added --ignore-whitenoise option
	# - Code cleanup in Packet class
	# - made Internet node optional

#0.1.2 (Basic routing rule support)
	# - Added support for routing rules in 
	#   the network.conf file.
	# - Bug Fixes

#0.1.1 (Cleanup and preparation)
	# - Updated TODO comments
	# - Cleaned up argument parsing
	# - More checks in place
	# - Begin preparation for routing support

#0.1.0 (Stable demo)
	# - Added scapy_sniff_pcap function
	# - Basic command line arg checks
	# - Config files now specificed via args
	# - Removed 'color' from nodes, network.conf
	# - Minor code cleanup

#0.0.3 (Pcap Support) 
	# - Added support for pcap files via cmd arg (1:1 timing)
	# - Added pcap timing option (hardcoded currently)

#0.0.2 (Visual Improvements)
	# - Fixed config file color reading issue
	# - Basic validation on config files now present
	# - Overall visual improvement
	#   - Added font support
	#   - Added (rough) image icon support
	#   - (Not perfect) text centering

#0.0.1 (First Version)
	#Initial Features:
	# - Reads in IP and coords from network.conf
	# - Reads in protocol filter from triggers.conf
	#	- (No trigger result customization)
	# - Displays rectangles for nodes, circles for packets
	# - Sniffs packets from network, displays all
	# - 1 Color for TCP, 1 for UDP
