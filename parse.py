#!/bin/python
import argparse 

parser = argparse.ArgumentParser()
parser.add_argument('-a', action='store', dest='ip_addr',
                    help='IP address')

parser.add_argument('-p', action='store', dest='port',
                    type=int, help='port')

results = parser.parse_args()
user_addr = results.ip_addr
user_port = results.port
print('ip_addr     =', results.ip_addr)
print('port   =', results.port)

def ip_address_def(user_addr, ss_addr, sd_addr):
  if user_addr is None:
    return False
  elif user_addr in ss_addr or user_addr in sd_addr:
    return True
  else:
    return False

def port_def(user_port, ss_port, sd_port):
  if ss_port == user_port or sd_port == user_port:
    return True
  else:
    return False

def both_def(user_addr, sniff_saddr, sniff_daddr, user_port, sniff_sport, sniff_dport):
  if ip_address_def(user_addr, sniff_saddr, sniff_daddr) == True and port_def(user_port, sniff_sport, sniff_dport) == True:
    return True
  else:
    return False

def nothing_def():
  if user_addr == 'None' and user_port == 'None':
    return True
  else:
    return False

def argum_test(sniff_saddr, sniff_daddr, sniff_sport, sniff_dport):
  if user_addr is not None and user_port is not None:
    if both_def(user_addr, sniff_saddr, sniff_daddr, user_port, sniff_sport, sniff_dport) == True:
      print('both_def')
      return 1
  elif user_port is not None:
    if port_def(user_port, sniff_sport, sniff_dport) == True:
      print('port_def')
      return 2
  elif user_addr is not None:
    if ip_address_def(user_addr, sniff_saddr, sniff_daddr) == True:
      print('ip_def')
      return 3
  elif nothing_def() == True:
    return 4
