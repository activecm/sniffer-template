#!/usr/bin/env python3
"""Listen for packets on an interface and..........."""
#Copyright 2018-2021 William Stearns <william.l.stearns@gmail.com>


__version__ = '0.3.2'

__author__ = 'William Stearns'
__copyright__ = 'Copyright 2018-2021, William Stearns'
__credits__ = ['William Stearns']
__email__ = 'william.l.stearns@gmail.com'
__license__ = 'GPL 3.0'
__maintainer__ = 'William Stearns'
__status__ = 'Prototype'				#Prototype, Development or Production


import os
import sys
import tempfile
import gzip												#Lets us read from gzip-compressed pcap files
import bz2												#Lets us read from bzip2-compressed pcap files

try:
	#from scapy.all import *
	from scapy.all import sniff, raw, Scapy_Exception, ARP, Ether, ICMP, IP, IPv6, PcapWriter, TCP, UDP	# pylint: disable=no-name-in-module,unused-import
	#from scapy.config import conf									#For future use in scapy "conf.use_pcap = True"
except ImportError:
	sys.stderr.write('Unable to load the scapy library.  Perhaps run   sudo apt install python3-pip || (sudo yum install python3-pip ; sudo pip3 install scapy )   ?\n')
	sys.stderr.flush()
	sys.exit(1)


def debug_out(output_string):
	"""Send debuging output to stderr."""

	if cl_args['devel']:
		sys.stderr.write(output_string + '\n')
		sys.stderr.flush()


def open_bzip2_file_to_tmp_file(bzip2_filename):
	"""Open up a bzip2 file to a temporary file and return that filename."""

	tmp_fd, tmp_path = tempfile.mkstemp()
	try:
		with os.fdopen(tmp_fd, 'wb') as tmp_h, bz2.BZ2File(bzip2_filename, 'rb') as compressed_file:
			for data in iter(lambda: compressed_file.read(100 * 1024), b''):
				tmp_h.write(data)
		return tmp_path
	except:
		sys.stderr.write("While expanding bzip2 file, unable to write to " + str(tmp_path) + ', exiting.\n')
		raise


def open_gzip_file_to_tmp_file(gzip_filename):
	"""Open up a gzip file to a temporary file and return that filename."""

	tmp_fd, tmp_path = tempfile.mkstemp()
	try:
		with os.fdopen(tmp_fd, 'wb') as tmp_h, gzip.GzipFile(gzip_filename, 'rb') as compressed_file:
			for data in iter(lambda: compressed_file.read(100 * 1024), b''):
				tmp_h.write(data)
		return tmp_path
	except:
		sys.stderr.write("While expanding gzip file, unable to write to " + str(tmp_path) + ', exiting.\n')
		raise


def save_packet(raw_packet, destination):
	"""Save interesting packets out to a pcap file.  These will be appended if the file exists."""
	#Note we have to handle where destination will be:
	#- None, do nothing
	#- a string (filename), so use existing persistent handle or create a new persistent handle and write to it.
	#####- a queue (multiprocessing.queues.queue), so write to that queue and let the appropriate handler take care of it.  (Not currently used by this function)

	if destination is None:
		pass
	elif isinstance(destination, str):
		if "save_handles" not in save_packet.__dict__:
			save_packet.save_handles = {}

		if destination not in save_packet.save_handles:
			save_packet.save_handles[destination] = None

		if destination:
			try:
				save_packet.save_handles[destination] = PcapWriter(filename=destination, append=True)
			except:
				debug_out("Unable to open " + destination + ", no packets will be saved.")

		if save_packet.save_handles[destination] is not None:
			save_packet.save_handles[destination].write(raw_packet)
	#else:								#More strictly, elif type(destination) is multiprocessing.queues.Queue:   , but we're not sure if that module has been imported.
	#	destination.put(raw_packet)


def packet_layers(pkt):
	"""Returns a list of packet layers."""

	layers = []
	counter = 0
	while True:
		layer = pkt.getlayer(counter)
		if layer is not None:
			#print(layer.name)
			layers.append(layer.name)
		else:
			break
		counter += 1

	return layers
	#Sample return	['Ethernet', 'IP', 'TCP']


def process_packet_source(if_name, pcap_source, user_args):
	"""Process the packets in a single source file, interface, or stdin."""

	source_file = None
	close_temp = False
	delete_temp = False

	#We have an interface to sniff on
	if if_name:
		debug_out('Reading packets from interface ' + if_name)
		try:
			if user_args['count']:
				sniff(store=0, iface=if_name, filter=user_args['bpf'], count=user_args['count'], prn=lambda x: processpacket(x))	# pylint: disable=unnecessary-lambda
			else:
				sniff(store=0, iface=if_name, filter=user_args['bpf'], prn=lambda x: processpacket(x))					# pylint: disable=unnecessary-lambda
		except ((Scapy_Exception, PermissionError)):
			sys.stderr.write("Unable to open interface " + str(pcap_source) + ' .  Permission error?  Perhaps runs as root or under sudo?  Exiting.\n')
			raise
	#Read from stdin
	elif pcap_source in ('-', None):
		debug_out('Reading packets from stdin.')
		tmp_packets = tempfile.NamedTemporaryFile(delete=True)											# pylint: disable=consider-using-with
		tmp_packets.write(sys.stdin.buffer.read())
		tmp_packets.flush()
		source_file = tmp_packets.name
		close_temp = True
	#Set up source packet file; next 2 sections check for and handle compressed file extensions first, then final "else" treats the source as a pcap file
	elif pcap_source.endswith('.bz2'):
		debug_out('Reading bzip2 compressed packets from file ' + pcap_source)
		source_file = open_bzip2_file_to_tmp_file(pcap_source)
		delete_temp = True
	elif pcap_source.endswith('.gz'):
		debug_out('Reading gzip compressed packets from file ' + pcap_source)
		source_file = open_gzip_file_to_tmp_file(pcap_source)
		delete_temp = True
	else:
		debug_out('Reading packets from file ' + pcap_source)
		source_file = pcap_source

	#Try to process file first
	if source_file:
		if os.path.exists(source_file) and os.access(source_file, os.R_OK):
			try:
				if user_args['count']:
					sniff(store=0, offline=source_file, filter=user_args['bpf'], count=user_args['count'], prn=lambda x: processpacket(x))	# pylint: disable=unnecessary-lambda
				else:
					sniff(store=0, offline=source_file, filter=user_args['bpf'], prn=lambda x: processpacket(x))				# pylint: disable=unnecessary-lambda
			except (FileNotFoundError, IOError):
				sys.stderr.write("Unable to open file " + str(pcap_source) + ', exiting.\n')
				raise
		else:
			sys.stderr.write("Unable to open file " + str(source_file) + ', skipping.\n')

	if close_temp:
		tmp_packets.close()

	if delete_temp and source_file != pcap_source and os.path.exists(source_file):
		os.remove(source_file)


#REPLACEME
def processpacket(p):
	"""Process a single packet p."""
	#Here is where you take your actions based on the packet.

	#Suggestions

	#==== Print out the packet so we can see how scapy labels each of the components
	#Just print the packet in a readable form.  It's helpful to see the packet structure to know what fields are available.
	#p.show()
	#If you just want to see one packet, add sys.exit to quit the program.
	#sys.exit(2)

	#==== Below is a block that pulls out the protocol, source and dest IPs and ports, and prints them along with the layers found in this packet
	all_layers = packet_layers(p)

	source_ip = ''
	dest_ip = ''
	if p.haslayer(IP):
		source_ip = p[IP].src
		dest_ip = p[IP].src
	elif p.haslayer(IPv6):
		source_ip = p[IPv6].src
		dest_ip = p[IPv6].src

	source_port = ''
	dest_port = ''
	p_proto = ''
	#if all_layers == ['Ethernet', 'Raw']:
	#	return
	#el
	if p.haslayer(Ether) and p[Ether].type == 0x88CC:
		pass
	elif p.haslayer(TCP) and isinstance(p[TCP], TCP):
		p_proto = 'TCP'
		#p[TCP].show()
		source_port = str(p[TCP].sport)
		dest_port = str(p[TCP].dport)
	elif p.haslayer(UDP) and isinstance(p[UDP], UDP):
		p_proto = 'UDP'
		#p[UDP].show()
		source_port = str(p[UDP].sport)
		dest_port = str(p[UDP].dport)
	elif p.haslayer(ICMP) and isinstance(p[ICMP], ICMP):
		p_proto = 'ICMP'
		#p[ICMP].show()
		source_port = str(p[ICMP].type)
		dest_port = str(p[ICMP].code)
	#IPv6 doesn't have a dedicated ICMPv6 layer, so we need to key off the IPv6 next_header value of 58 for ICMPv6
	elif p.haslayer(IPv6) and p.getlayer(IPv6).nh == 0:	#0: Hop-by-hop options header
		hbh_layer = p.getlayer('IPv6').payload
		if hbh_layer.nh == 58:
			ICMP6_layer = hbh_layer.payload
			p_proto = 'ICMP6'
			#ICMP6_layer.show()
			source_port = str(ICMP6_layer.type)
			try:
				dest_port = str(ICMP6_layer.code)
			except:
				dest_port = 'unspec'
		else:
			p.show()
			sys.exit(2)
	elif p.haslayer(IPv6) and p.getlayer(IPv6).nh == 58:	#58: ICMPv6
		ICMP6_layer = p.getlayer('IPv6').payload
		p_proto = 'ICMP6'
		#ICMP6_layer.show()
		source_port = str(ICMP6_layer.type)
		dest_port = str(ICMP6_layer.code)
	elif p.haslayer(ARP) and isinstance(p[ARP], ARP):
		if p[ARP].op == 1:
			#Request/query
			p_proto = 'ARP_q'
		elif p[ARP].op == 2:
			#Reply
			p_proto = 'ARP_r'
		#p[ARP].show()
		#sys.exit(2)
		source_ip = str(p[ARP].psrc) + "/" + str(p[ARP].hwsrc)
		source_port = ''
		dest_ip = str(p[ARP].pdst) + '/' + str(p[ARP].hwdst)
		dest_port = ''
	elif p.haslayer(IP) and p[IP].proto == 2:		#IGMP
		p_proto = 'IGMP'
		#p.show()
		source_port = 'unspec'
		dest_port = 'unspec'
	else:
		p.show()
		#If you just want to see one packet, add sys.exit to quit the program.
		sys.exit(2)

	#The following block removes secondary layers from view.  Don't use this if you want to see all available layers.
	for dont_want in layers_to_ignore:
		while dont_want in all_layers:
			all_layers.remove(dont_want)

	all_layers_out = str(all_layers).replace("'", "").replace(", DNS Resource Record, DNS Resource Record, DNS Resource Record, DNS Resource Record", ", DNS Resource Record").replace(", DNS Resource Record, DNS Resource Record", ", DNS Resource Record").replace(", DNS Resource Record, DNS Resource Record", ", DNS Resource Record").replace(", DNS Resource Record, DNS Resource Record", ", DNS Resource Record")

	print("{0:5s} {1:>38s}/{2:6s} -> {3:>38s}/{4:6s} {5:40s}".format(p_proto, source_ip, source_port, dest_ip, dest_port, all_layers_out))


	#==== Look for interesting/malicious characteristics so we can save these to disk
	is_interesting = False

	#Note that many of these need the above block of code to set IP addresses and ports
	if (source_port == 7 and dest_port == 19) or (source_port == 19 and dest_port == 7):			#echo-chargen
		is_interesting = True

	#Other interesting things to check:
	#Is IPv4 and has IP options (IHL field > 5)
	#Is TCP and has _no_ TCP options (tcp header len = 5)
	#Has ethernet layer and Source and dest IP equal
	#Has ethernet layer and source IP or dest IP starts with 127.
	#Is IPv4 and source IP starts with 224-255
	#Is TCP and dest IP starts with 224-255
	#Evil bit turned on. :-)
	#Telnet/rcommands used
	#Has tcp header and has invalid TCP flag combinations
	#Packets that are too small
	#ping of death packets						https://en.wikipedia.org/wiki/Ping_of_death
	#Possibly ICMP redirects
	#Has IP header and IP version other than 4 or 6
	#Has IP header and reserved bit != 0
	#Has IP header and invalid fragmentation combinations
	#	too small fragments and MF set
	#Has UDP header and one of the ports is disallowed by policy
	#Has TCP header and one of the ports is disallowed by policy
	#Has TCP header and reserved bits != 0
	#Has IP header and IP Proto is not 1, 6, 17, 50, or 51
	#Has IPv6 header and nh is not 1, 6, 17, 50, or 51 (check values)


	if is_interesting and cl_args['write']:		#If the packet is worth saving for later and the user specified a filename to which to write it,
		save_packet(p, cl_args['write'])


layers_to_ignore = ('DNS EDNS0 TLV',
                    'DNS DNSKEY Resource Record',
                    'DNS DS Resource Record',
                    'DNS NSEC Resource Record', 'DNS NSEC3 Resource Record',
                    'DNS OPT Resource Record',
                    'DNS RRSIG Resource Record',
                    'DNS SOA Resource Record',
                    'ICMPv6 MLDv2 - Multicast Address Record',
                    'ICMPv6 Neighbor Discovery Option - Destination Link-Layer Address',
                    'ICMPv6 Neighbor Discovery Option - Prefix Information',
                    'ICMPv6 Neighbor Discovery Option - Recursive DNS Server Option',
                    'ICMPv6 Neighbor Discovery Option - Route Information Option',
                    'ICMPv6 Neighbor Discovery Option - Source Link-Layer Address',
                    'IPv6 Extension Header - Hop-by-Hop Options Header',
                    'PadN', 'Padding',
                    'Raw',
                    'SMBNegociate Protocol Request Header Generic')


if __name__ == '__main__':
	import argparse

	#REPLACEME
	parser = argparse.ArgumentParser(description='__sniffer_tmplate version ' + str(__version__))
	parser.add_argument('-i', '--interface', help='Interface from which to read packets', required=False, default=None)
	parser.add_argument('-r', '--read', help='Pcap file(s) from which to read packets', required=False, default=[], nargs='*')
	parser.add_argument('-w', '--write', help='Pcap file to which to save packets', required=False, default=None)
	parser.add_argument('-d', '--devel', help='Enable development/debug statements', required=False, default=False, action='store_true')
	parser.add_argument('-b', '--bpf', help='BPF to restrict which packets are processed', required=False, default='')
	parser.add_argument('-c', '--count', help='Number of packets to sniff (if not specified, sniff forever/until end of pcap file)', type=int, required=False, default=None)
	(parsed, unparsed) = parser.parse_known_args()
	cl_args = vars(parsed)

	debug_out("BPF we'll use is: " + cl_args['bpf'])


	read_from_stdin = False		#If stdin requested, it needs to be processed last, so we remember it here.  We also handle the case where the user enters '-' more than once by simply remembering it.
	if cl_args['interface'] is None and cl_args['read'] == []:
		debug_out('No source specified, reading from stdin.')
		read_from_stdin = True

	try:
		if cl_args['read']:
			#Process normal files first.
			for one_source in cl_args['read']:
				if one_source == '-':
					read_from_stdin = True
				else:
					process_packet_source(None, one_source, cl_args)

		#Now that normal files are out of the way process stdin and/or reading from an interface, either of which could be infinite.
		if read_from_stdin:
			process_packet_source(None, '-', cl_args)

		if cl_args['interface']:
			process_packet_source(cl_args['interface'], None, cl_args)
	except KeyboardInterrupt:
		pass
