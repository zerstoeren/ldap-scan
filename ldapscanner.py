#!/usr/bin/env python

import sys
import os
import argparse
import io
import json
import time
import netaddr
import threading
import ldap
import ldap.async
from socket import *

def ldapscan(server, port, proto):
    print "Attempting LDAP scan on " + '%s' % server + '\n'
    ts = time.time()
    ldap_srv = ldap.async.LDIFWriter(
    ldap.initialize(proto + "://" + server + ":" + str(port)),
    sys.stdout
)
    ldap_srv.startSearch(
      'dc=*,dc=*',
      ldap.SCOPE_SUBTREE,
      '(objectClass=*)',
)
    try:
        partial = ldap_srv.processResults()
    except Exception, errorcode:
        if errorcode[0] == 'ldap.NO_SUCH_OBJECT':
            print(server + ": " + errorcode[0] + "\n")
# move the code below to the proper location in the code... duh  lol
#       elif errorcode[0] == 'ldap.SERVER_DOWN':
#            try:
#                connector = socket(AF_INET. SOCK_STREAM)
#                connector.settimeout(1)
#                connector.connect(('%s' % server, port))
#                connector.send('Friendly Portscanner\r\n')
#                ldap_srv = connector.recv(2048)
#                connector.close()
#                print("[-] " + '%s' % server + ": " + '%s' % ldap_srv + '\n')
#            except Exception, errocode:
#                if errorcode[0] == "timed out":
#                    print(server + ": connection " + errorcode[0] + "\n")
#                    pass
#                elif errorcode[0] == "connection refused":
#                    print(server + ": connection " + errorcode[0] + "\n")
#                    pass
#                else:
#                    pass
        else:
            pass
    except ldap.SIZELIMIT_EXCEEDED:
        print('Warning: Server-side size limit exceeded.\n')
    else:
        if partial:
            print('Warning: Only partial results received.\n')

    print('[+] ' + server + ', is_ldap: True, LDAP Objects Received: %d \n' % (
      ldap_srv.endResultBreak-ldap_srv.beginResultsDropped
  )
)

#def thread_check(server, results_file):
def thread_check(server, port, proto):
    global semaphore

    try:
#        ldapscan(server, port, ldapargs.proto, results_file)
        ldapscan(server, port, proto)
    except Exception as e:
        with print_lock:
           print "I ended up here \n"
           print "[ERROR] [%s] - %s" % (server, e)
    finally:
        semaphore.release()

if __name__ == "__main__":
    ldapparser = argparse.ArgumentParser(description="LDAP Scanner")
    ldapparser.add_argument("-netrange", type=str, required=False, help="CIDR Block")
    ldapparser.add_argument("-ip", type=str, required=False, help="IP address to scan")
    ldapparser.add_argument("-port", type=int, required=True, help="Ports to scan for LDAP or LDAPS")
    ldapparser.add_argument("-proto", type=str, required=True, help="LDAP or LDAPS")
    ldapparser.add_argument("-results_file", type=str, required=False, help="Results File")
    ldapparser.add_argument("-packet_rate", default=1, type=int, required=False, help="Packet rate")
    ldapargs = ldapparser.parse_args()

    semaphore = threading.BoundedSemaphore(value=ldapargs.packet_rate)
    print_lock = threading.Lock()

    if ldapargs.ip is not None:
#        ldapscan(ldapargs.ip, ldapargs.port, ldapargs.proto, ldapargs.results_file)
        ldapscan(ldapargs.ip, ldapargs.port, ldapargs.proto)

    elif ldapargs.netrange is not None:
       for ip in netaddr.IPNetwork(ldapargs.netrange).iter_hosts():
#           ldapscan(str(ip), ldapargs.port, ldapargs.results_file)
           ldapscan(str(ip), ldapargs.port, ldapargs.proto)     

    elif not ldapargs.packet_rate and ldapargs.netrange:
       for ip in netaddr.IPNetwork(ldapargs.netrange).iter_hosts():
           semaphore.acquire()
#           ldapthread = threading.Thread(target=thread_check, args=(str(ip), ldapargs.results_file))
           ldapthread = threading.Thread(target=thread_check, args=(str(ip), ldapargs.port, ldapargs.proto)) 
           ldapthread.start()
           ldapthread.join()
    else:
        print "Please provide with either -ip or -netrange.  Or ./ldapscanner.py -h for help.."
        exit
