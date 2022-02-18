# sniffer-template
Template for building a packet sniffer

This is a ready-to-go base for building your custom packet sniffer.
# Steps
- Make sure python3 and scapy are installed
- Copy this script to your script name
- Edit any sections marked "REPLACEME".  This will include the trivial "...description='__sniffer_tmplate version '..." and the processpacket function


# processpacket
- "processpacket" is handed each sniffed packet one at a time as the object "p".
- Scapy has already identified the headers in the packet.  To see what's been identified, run "p.show()"
- The lines that are currently in processpacket are examples, and can be deleted.
- You can:
	1. Print information about each packet
	2. Collect statistics on the entire packet stream
	3. Save some packets to an output file
	4. Do a test (like "if p.haslayer(TCP) and p[TCP].dport == 443:") and process those differently


# Features
- Can sniff from an interface, one or more pcap files, or stdin.
- If reading from stdin, it saves all packets to a file and processes that, so it's not processing them live.
- Automatically decompresses gzip and bzip2 compressed pcap files.
- Code is in place to save packets that you feel should be saved


# Requirements
Scapy
Python3

