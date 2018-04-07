import dpkt
import socket
import pygeoip
import pcap
from urllib2 import urlopen
from contextlib import closing
import json
from netaddr import *
import os
import urllib2
import ipgetter

gi = pygeoip.GeoIP('GeoLiteCity.dat')
URL = ["example.com","youtube.com","/doc/tutorial/program_structure/","/R/A1MKIEFCMjc5MjE1NUVCNDQzNURCQjZGMEMxNzYwRTkxQjQwEgQAEAUXGK4BIgEBKgcIBBDT8cxQMgoIABDs9MxQGIACOICAnGBIgICAgPr_____AQ==",
       "/posts/18863414/accepted-answer-date?_=1494408626178","/questions/18863309/the-equivalent-of-a-goto-in-python"]
IP = []
src = []
dst = []


def check_http(f):
    for (ts,buf) in f:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data
            if tcp.dport == 80 and len(tcp.data) > 0:
                http = dpkt.http.Request(tcp.data)
                http_uri = http.uri
                validate_blacklisted_URL(http_uri,eth)
        except Exception, e:
            print e
            #print 'Error in checking HTTP '

def validate_blacklisted_URL(http_uri,eth):
    try:
        for i in range(len(URL)):
            if(http_uri == URL[i]):
                IP.append(eth.data)
                print '*******************************************************************************'
                print 'Black listed URI ' + http_uri
                for j in range(len(IP)):
                    src.append(socket.inet_ntoa(IP[j].src))
                    dst.append(socket.inet_ntoa(IP[j].dst))               
                    if(IPAddress(src[j]).is_private()):
                        src[j] = ipgetter.myip()
                        print '[+] Source: ' + src[j] + ' --> [*] Destination: ' + dst[j]
                        printRecord(src[j])
    except Exception, e:
            print e
                    
      
    

def printRecord(src_tmp):
    try:
	rec = gi.record_by_name(src_tmp)
	city = rec['city']
	country = rec['country_name']
	long = rec['longitude']
	lat = rec['latitude']
	print '[*] Target: ' + src_tmp + ' Geo-located. '
	print '[+] '+str(city)+', '+str(country)
	print '[+] Latitude: '+str(lat)+ ', Longitude: '+ str(long)
	print '*******************************************************************************'
    except Exception, e:
        print 'Unregistered'

def main():
    try: 
        f = pcap.pcap(name=None, promisc=True, immediate=True)
        f.setfilter('dst port 80')
        print '[*] Started Sniffing on eth0'
        check_http(f)
    except KeyboardInterrupt:
        raise

if __name__ == '__main__':
     main()    
    


