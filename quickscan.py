#!/usr/bin/env python2.7

import sys
import json
import time
import socket
import argparse

from ipwhois import IPWhois
from pprint import pprint
from threading import Thread
from blessings import Terminal

t = Terminal()

# Input validation, print logo
if not len(sys.argv[1:]):
	print t.cyan("""
             _      _                        
            (_)    | |                       
  __ _ _   _ _  ___| | _____  ___ __ _ _ __  
 / _` | | | | |/ __| |/ / __|/ __/ _` | '_ \ 
| (_| | |_| | | (__|   <\__ \ (_| (_| | | | |
 \__, |\__,_|_|\___|_|\_\___/\___\__,_|_| |_|
    | |                                      
    |_|                Welcome to QuickScan.



To start using this script please provide a command 
line argument and it's corresponding value, where. 
To display all options available use -h or --help.

Example:
knocker.py -h
knocker.py --resolve google.com 
knocker.py --scan 192.168.55.88 -v               \n	""")
	sys.exit(0)

# Handle command line arguments
parser = argparse.ArgumentParser(description="This program functions as a simple port scanner & domain utility.")
parser.add_argument("-r", "--resolve", help="enter a domain to resolve")
parser.add_argument("-w", "--whois", help="query WHOIS on target host")
parser.add_argument("-s", "--scan", help="specify the host(IP) you wish to scan")
parser.add_argument("-v", "--verbose", action="store_true", help="toggle verbosity")
args = parser.parse_args()

host = args.target

if args.resolve:	
	try:
		data = socket.gethostbyname_ex(args.resolve)
		print "\n[" + t.green("+") + "]Domain resolves to: \n" + repr(data) + "\n"
	
	except socket.gaierror as e:
		if args.verbose == True:
			print "[" + t.red("!") + "]Critical. A GAIerror was raised with the following error message."
			print e + "\n"
			print "[" + t.green("+") + "]Consider typing the domain without the protocol, I.E. 'google.com, instead of http://google.com"
			sys.exit(0)
		else:
			print "[" + t.red("!") + "]Critical. An error was raised while attempting to resolve domain."
			sys.exit(0)
	
	# Format for logging
	format_resolve = json.dumps(data, indent = 2)
	
	# Save results to log file
	with open("quickscan.log", "ab")as outfile:
		outfile.write("Resolved " + args.resolve )
		outfile.write(format_resolve)
		outfile.write("\n\n")
		outfile.close

	print "\n[" + t.green("+") + "]Results saved to 'quickscan.log' in the current working directory."

if args.whois:
	try:
		obj = IPWhois(args.whois)
		results = obj.lookup_rdap(depth=1)
		pprint(results)
	except Exception as e:
		if args.verbose == True:
			print "[" + t.red("!") + "]Critical. An error was raised while performing WHOIS with the following message."
			print e 
			sys.exit(0)
		else:
			print "[" + t.red("!") + "]Critical. An error was raised while attempting to resolve domain."
			sys.exit(0)
	
	# Format for logging
	format_whois = json.dumps(results, indent = 2)
	
	# Save logs
	with open("quickscan.log", "ab")as outfile:
		outfile.write("WHOIS lookup results for " + args.whois + "\n")
		outfile.write(format_whois)
		outfile.write("\n\n")
		outfile.close
	
	print "\n[" + t.green("+") + "]Results saved to 'quickscan.log' in the current working directory."

# Scanner code adapted for this program from the original implementation
# by TheZ3ro. Reference https://gist.github.com/TheZ3ro/7255052 for details.

if args.target:
	print "\n[" + t.green("+") + "]Please enter a port range.\n"
	start_port = input("Start port:  ")
	end_port = input("End port:  ")   
	print
	
	counting_open = []
	counting_close = []
	threads = []

	def scan(port):
		s = socket.socket()
		
		try:
			result = s.connect_ex((host,port))
		except socket.gaierror as e:
			if args.verbose == True:
				print "[" + t.red("!") + "]Critical. A GAIerror was raised with the following error message."
				print e 
				sys.exit(0)
			else:
				print "[" + t.red("!") + "]Critical. An error was raised while attempting to connect."
				sys.exit(0)
			
		if args.verbose == True:
			print "\n[" + t.green("+") + "]working on port: " + str(port)
			time.sleep(0.250)      
	
		if result == 0:
			counting_open.append(port)
			if args.verbose == True:
				print "\n[" + t.magenta("~") + "]" + str(port) + " -> open." 
				time.sleep(0.250)
			s.close()
		else:
			counting_close.append(port)
			if args.verbose == True:
				print "\n[" + t.magenta("~") + "]" + str(port) + " -> closed." 
				time.sleep(0.250)
			s.close()
	
	for items in range(start_port, end_port+1):
		tr = Thread(target=scan, args=(items,))
		threads.append(tr)
		tr.start()
	
	[x.join() for x in threads]
	
	for ports in (counting_open):
		print "[" + t.magenta("~") + "]" + str(ports) + " -> open."
		
	print "\n[" + t.green("+") + "]Scan completed."
	
	# Save port scan results
	with open("quickscan.log", "ab")as outfile:
		outfile.write("Port Scan Results for " + host + "\n")
		outfile.write("Open Ports\n")
		for line in counting_open:
			outfile.write(str(line))
			outfile.write("\n")
		outfile.write("\n\n")
		outfile.close()
		
	print "\n[" + t.green("+") + "]Results saved to 'quickscan.log' in the current working directory."	
