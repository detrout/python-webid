#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
This script should be run separately to sniff the wireless probe requests. 
It fills the first_seen and last_seen values of the mac addresses.
'''

import datetime
import logging
import signal
import sys
sys.path.append('../')

import sqlalchemy.orm.exc

from scapy.all import *

import webid.sniffer
from webid.sniffer.mac_sniffer import Device


logger = logging.getLogger(name=__name__)
session = webid.sniffer.createDB_and_session()

class ProbeRequests():
	def __init__(self):
		self.burst_sizes = []
		self.burst_inter_intervals = []
		self.burst_duration = []
		self.first_seen = 0
		self.last_seen = 0
		self.current_burst_count = 0
		
	def update(self):
		d =   datetime.datetime.now()
		if self.last_seen == 0:
			self.last_seen = d
			self.first_seen = d
			self.current_burst_count = 1
		elif (d - self.last_seen).seconds < 4:
			# existing burst
			self.current_burst_count += 1
			self.last_seen = d
		else :
			#new burst
			self.burst_sizes.append(self.current_burst_count)
			self.burst_inter_intervals.append((d - self.first_seen).seconds)
			self.burst_duration.append((self.last_seen - self.first_seen).seconds)
			self.first_seen = d
			self.last_seen = d
			self.current_burst_count = 1
	def __str__(self):
			return """   
			Burst Sizes: %s   
			Burst inter: %s    
			Burst Duration: %s   
			First Seen: %s   
			Last Seen: %s    
			Current Burst Size:%d
			"""%(self.burst_sizes, self.burst_inter_intervals, 
			self.burst_duration,self.first_seen,self.last_seen,
			self.current_burst_count)  
	
			


requesters = {}
def PacketHandler(pkt):
	if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 4:
# 		if requesters.has_key(pkt.addr2):
# 			requesters[pkt.addr2].update()
# 		else:
# 			requesters[pkt.addr2] = ProbeRequests()
# 			requesters[pkt.addr2].update()
		try:
			device = session.query(Device).filter_by(mac=pkt.addr2).one()
			device.update_last_seen()
		except sqlalchemy.orm.exc.NoResultFound:
			session.add(Device(MAC=pkt.addr2))
			session.commit()
			
		#  " -- Client with MAC: %s probing for SSID: %s" % (pkt.addr2,pkt.info)


sniff(iface="mon0", prn = PacketHandler,store=0)


def signal_handler(signal, frame):
        for k,v in requesters.iteritems():
			print "MAC:%s,%s"%(k,v)        
			
        sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)
print 'Press Ctrl+C'
signal.pause()


			
			
		

