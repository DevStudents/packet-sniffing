#!/bin/python
import socket, sys
from struct import *
from parse import *
 
test_value = 0

try:
  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
except socket.error as msg:
  print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
  sys.exit()
 
# receive a packet
while True:
  packet = s.recvfrom(65565)
  packet = packet[0]
   
  # parse ethernet header
  eth_length = 14
  eth_header = packet[:eth_length]
  eth = unpack('!6s6sH' , eth_header)
  eth_prot = socket.ntohs(eth[2])

  # parse IP packets, IP Protocol number = 8
  if eth_prot == 8 :
    # parse IP header take first 20 characters for the ip header
    ip_header = packet[eth_length:20+eth_length]
    iph = unpack('!BBHHHBBH4s4s', ip_header)
    ver_ihl = iph[0]
    ver = ver_ihl >> 4
    ihl = ver_ihl & 0xF
    iph_length = ihl * 4
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])
    if results.ip_addr == 'None':
    	if ip_address_def(results.ip_addr, s_addr, d_addr) == True:
    	  print('Version : ' + str(ver) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))

    # TCP protocol
    if protocol == 6 :
      t = iph_length + eth_length
      tcp_header = packet[t:t+20]
      tcph = unpack('!HHLLBBHHH', tcp_header)
      src_port = tcph[0]
      dst_port = tcph[1]
      seq = tcph[2]
      ack = tcph[3]
      doff_reserved = tcph[4]
      tcph_length = doff_reserved >> 4
      test_value = argum_test(s_addr, d_addr, src_port, dst_port)
       
      if test_value == 3:
        print('TCP: Source Port : ' + str(src_port) + ' Dest Port : ' + str(dst_port) + ' Sequence Number : ' + str(seq) + ' Acknowledgement : ' + str(ack) + ' TCP header length : ' + str(tcph_length))
      elif test_value == 2:
        print('TCP: Source Port : ' + str(src_port) + ' Dest Port : ' + str(dst_port) + ' Sequence Number : ' + str(seq) + ' Acknowledgement : ' + str(ack) + ' TCP header length : ' + str(tcph_length))
      elif test_value == 1:
        print('TCP: Source Port : ' + str(src_port) + ' Dest Port : ' + str(dst_port) + ' Sequence Number : ' + str(seq) + ' Acknowledgement : ' + str(ack) + ' TCP header length : ' + str(tcph_length))
      #else:
      #  print('Source Port : ' + str(src_port) + ' Dest Port : ' + str(dst_port) + ' Sequence Number : ' + str(seq) + ' Acknowledgement : ' + str(ack) + ' TCP header length : ' + str(tcph_length))
      ## get data from the packet
      #h_size = eth_length + iph_length + tcph_length * 4
      #data = packet[h_size:]
      #print(data)

    # ICMP Packets
    elif protocol == 1 :
      u = iph_length + eth_length
      icmph_length = 4
      icmp_header = packet[u:u+4]
      icmph = unpack('!BBH', icmp_header)
      icmp_type = icmph[0]
      code = icmph[1]
      checksum = icmph[2]
      if test_value == 3:
      	print('ICMP: Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum))
      elif test_value == 2:
        print('ICMP: Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum))
      elif test_value == 1:
        print('ICMP: Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum))
      #else:
      #  print('ICMP: Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum))

      # get data from the packet
      #h_size = eth_length + iph_length + icmph_length
      #data = packet[h_size:]
      #print(data)

    # UDP packets
    elif protocol == 17 :
      u = iph_length + eth_length
      udph_length = 8
      udp_header = packet[u:u+8]
      udph = unpack('!HHHH', udp_header)
      src_port = udph[0]
      dst_port = udph[1]
      length = udph[2]
      checksum = udph[3]
       
      #if ip_address_def(results.ip_addr, s_addr, d_addr) == True:
      #  print('UDP: Source Port : ' + str(src_port) + ' Dest Port : ' + str(dst_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum))
      #else:
      #  print('UDP: Source Port : ' + str(src_port) + ' Dest Port : ' + str(dst_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum))
       
      ## get data from the packet
      #h_size = eth_length + iph_length + udph_length
      #data = packet[h_size:]
      #print(data)

    # some other IP packet like IGMP
    else :
      print('Protocol other than TCP/UDP/ICMP')
         
    #print()
