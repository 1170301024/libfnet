#!/usr/bin/python3.8

import re 
import sys

pcap_Filepath = sys.argv[1]
log_Filepath = sys.argv[2]

logfile = open(logFilepath, 'w')
data_file = open('1.txt', 'w')

action2tls={}
for line in logfile:
   log_match = re.match( r'{"action": (.*), "stream_id": "(.*)", "request": [(.*)], "response": [(.*)]}', line, re.M|re.I)
   action = line_match.group(1)
   stream_id = line_match.group(2)
   request_pkt_seq = line_match.group(3).split(', ')
   response_pkt_seq = line_match.group(4).split(', ')
   for l in data_file:
      
      data_match = re.match(r''+)
   



