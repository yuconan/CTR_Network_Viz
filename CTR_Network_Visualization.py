#!/usr/bin/env python3

#Network (attack) visualization tool Proof-Of-Concept / Pre-Alpha
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

#initialize screen
screen_width = 800
screen_height = 450
screen = None
pygame.display.set_caption("CTR Network Visualization Tool (v.0.1.1)")
#placeholder for app exit var
done = False
#IP address font (bundled TTF)
font = pygame.font.Font("Monterey-Bold.ttf", 20)


#list of nodes (computers on network to display)
nodes = []
#list of packets currently active
packets = []
#trigger list (read from conf file)
triggers = []

#packet colors
color_udp = "#00ff00"
color_tcp = "#ff0000"
color_trigger = "#000000"

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
		if p[IP].src == node.ip:
			src = node.ip
		if p[IP].dst == node.ip:
			dst = node.ip
	#if src == dst, usually Internet == Internet, 
	# usually caused by communication between nodes
	# not included in network.conf. 
	if src == dst: 
		return #ignore packet, do not draw
			
	#Color based on TCP or UDP
	try:
		p[TCP]
		color = color_udp
	except:
		color = color_tcp

	#Process triggers
	for t in triggers:
			#Protocol (layer) trigger
			if t.startswith("protocol="):
				proto = str(t.split("=")[1].strip().upper())
				if proto in p: #find layer in packet
					color = color_trigger
					size = 13

	packets.append ( Packet( src, dst, color, size) )

#Sniff network, call callback function on each packet
def scapy_sniff():
	sniff(filter="ip",prn=scapy_callback) 

#Automatic sniffing from pcap (realtime)
def scapy_sniff_pcap(path):
	sniff(filter="ip", prn=scapy_callback, offline=path, store=0)

#Parse pcap file manually. This reads all into memory, and can
#  support custom time acceleration, etc.
def scapy_parse_pcap(path, accel=1.0):
	cap = rdpcap(path)
	index = 0
	curr_time = cap[index].time #time of last packet displayed

	while index < len(cap):
		#Get packet to display
		pkt = cap[index]
		#Display packet
		scapy_callback(pkt)
		try:
			#Delay between current packet and next
			delay = (cap[index+1].time - curr_time)/accel
			#Update current time
			curr_time = cap[index+1].time
			#Update index
			index+= 1
		except: #Ran out of packets or error
			break
		sleep(delay)
	return
	

#========================== Data Manipulation Functions ==========================

#get node from node list by IP address
def getNodeByIP(ip_addr):
	for node in nodes:
		if node.ip == ip_addr:
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

#Validate file
def isFile(path):
	return os.path.isfile(path)


#Read & parse network.conf
def read_network_config(path="network.conf"):
	f = open(path)
	for line in f.readlines():
		#Skip commented or blank lines
		if line.startswith("//") or line.isspace():
			continue

		arr = line.split(" ")
		#Determine device type (the string 'type' itself is reserved)
		#TODO: Checks here
		kind = str(arr[0]).strip().upper()
		if kind == "NODE":
			#Parse Node
			try:
				#basic parsing
				ip = str(arr[1])
				x = int(arr[2])
				y = int(arr[3])
				path = str(arr[4]).strip()
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

			#Parse Routers (TODO)

		else:
			print("Invalid device type on network cfg line: \'" + str(line).strip() + "\', skipping")
			continue

		nodes.append( Node(ip, x, y, path) )
	f.close()
	return

#Read, validate triggers.conf
def read_triggers_config(path="triggers.conf"):
	f = open(path)
	for line in f.readlines():
		#Skip commented out lines
		if line.startswith("//"):
			continue

		#Validate, add protocol trigger
		if line.startswith("protocol=") and len(line.split("=")[1].strip()) <= 5:
			triggers.append(str(line))
		else:
			print("Skipping invalid trigger: \'" + line.strip() + "\'")
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

	# "constructor"
	def __init__(self, new_ip, x_pos, y_pos, img_path=None):
		self.ip = new_ip
		self.x = x_pos
		self.y = y_pos
		self.img = pygame.image.load(img_path)

	#Display self
	def update(self):
		#Draw Image
		screen.blit(self.img, (self.x,self.y))
		#Draw Rectangle
	##	else:
	##		pygame.draw.rect(screen, self.color, pygame.Rect(self.x,self.y,60,60))
		#display text
		text = font.render(self.ip, True, (0,0,0))
		text_width, text_height = font.size(self.ip)

		screen.blit(text, (self.x-(text_width/4), self.y+70))

#One packet to be displayed
class Packet:
	unique_id = None #UUID
	size = 5
	x = 0 #current position
	y = 0
	target_x = 0 #target coords
	target_y = 0
	vector = [] #direction vector

	color = pygame.Color("#ff0000")

	def __init__(self, src_ip, target_ip, c="#ff0000", s=5):
		#set starting coords to center of source square
		self.x = getNodeByIP(src_ip).x+30
		self.y = getNodeByIP(src_ip).y+30
		#set target coords
		self.target_x = getNodeByIP(target_ip).x+30
		self.target_y = getNodeByIP(target_ip).y+30
		#set color
		self.color = pygame.Color(c)
		#set size
		self.size = s

		#Add small amount of randomness to starting & target coords
		#  for aesthetics. Makes packets not all happen on a single line
		self.x+=random.uniform(-5,5)
		self.y+=random.uniform(-5,5)

		self.target_x+=random.uniform(-5,5)
		self.target_y+=random.uniform(-5,5)

		#calculate movement vector
		self.vector = calc_vector(self.target_x, self.target_y, self.x, self.y, 10)
		#generate a UUID for packet identification for deletion
		self.unique_id = uuid.uuid4() 


	#Delete self if necessary, move, & draw
	def update(self):
		#Shrink as approaching destination
		if abs(self.x - self.target_x) < 20 and abs(self.y - self.target_y) < 20:
			self.size = int(self.size/2)

		#If packet is very close to destination, delete
		if( abs(self.x - self.target_x) < 10 and abs(self.y - self.target_y) < 10):
			for p in packets: #find self in list
				if p.unique_id == self.unique_id: #identify by UUID
					packets.remove(p) #delete
					break
		else:
			#draw
			self.x+=self.vector[0]
			self.y+=self.vector[1]
			pygame.draw.circle(screen, (self.color), (int(self.x),int(self.y)), self.size)

#========================== Main ==========================

#Validate args
if len(sys.argv) < 2:
	print("Usage: python3 <script>.py PATH_OF_network.conf PATH_OF_triggers.conf file.pcap")
	print("  If a pcap is not provided, script will sniff on default network interface")
	exit(1)
if not (isFile(sys.argv[1]) and isFile(sys.argv[2])):
	print("Config file not found")
	exit(1)


#Read, parse network.conf
read_network_config(sys.argv[1])

#Read, parse triggers.conf
read_triggers_config(sys.argv[2])

#Determine if user passed a pcap file
if len(sys.argv) > 3:
	thread.start_new_thread(scapy_sniff_pcap, (sys.argv[3],) )
else:
	#Launch network sniffer on thread 2 (gotta love Python)
	thread.start_new_thread(scapy_sniff, ())

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

	#display all nodes
	for node in nodes:
		node.update()

	#display all packets
	for packet in packets:
		packet.update()

	#update screen (double buffering)
	pygame.display.flip()


#TODO:
	# -> Add routing support (w/ n-hops, failures) <-
	# - Add packet display scaling option
	# -> Add more trigger options <-
	# - Add internal app menu system
	#	- Pop-ups
	#	- Menu bar
	#	- Overhaul saving/loading
	#	- Internal network setup

#Minor TODO:
	# - Add support for multiple simultaneous inputs
	# - Add more icons, etc.
	# - Graphical improvements

#========================== Changelog ==========================

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